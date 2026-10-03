# Analisador de regras

`src/` contém o parser, o algoritmo e o pipeline em C++; `tests/` contém
os testes do analisador. `extract_original_rules.py` recupera originais por
SID, e `generate_rule_groups.py` gera os três pares original/adaptado.

## Compilar e usar

Na raiz de `tcc`:

```bash
make alg
./build/alg transport-rules/original-tcp-udp.rules build/transport-adapted.rules \
  > build/transport-summary.txt
make rule-groups
make test
```

`make alg` compila em `analisador/build/` e copia o executável para `build/alg`.
Para compilar apenas nesta pasta: `make -C analisador`. O binário depende de
C++ e Make, pode ser copiado para outro diretório e recebe os caminhos de
entrada e saída como argumentos. O resumo dos intervalos sai na saída padrão.

`make -C analisador test` executa somente a suíte do analisador, com UBSan nos
testes C++. Os testes Python também usam a base e os grupos na raiz do projeto.

## Grupos de regras

A classificação usa o protocolo do cabeçalho original, antes da adaptação.
Mensagens, metadados e nomes de flowbits não alteram o grupo.

| Grupo | Protocolos | Aceitas | Adaptadas no payload |
|---|---|---:|---:|
| Aplicação | HTTP, SMB e SSH | 4 | 4 |
| Transporte | TCP, UDP, tcp-pkt, tcp-stream e SCTP | 1.005 | 71 |
| Rede/IP | IP, IPv6, ICMP, ICMPv6 e pkthdr | 526 | 0 |

São 1.535 regras aceitas entre 52.508, incluindo 1.460 mantidas sem alteração.
Cada regra pertence a um grupo. A geração recupera os originais por SID e
recalcula os offsets com os intervalos de cada grupo. Os testes verificam
cobertura, ausência de duplicação e reprodução dos arquivos e summaries.
As quatro SIDs de aplicação são 2024212, 2057247, 2008605 e 2009477.

## Escopo do algoritmo

Os intervalos são inclusivos e relativos ao **payload de cada pacote**.
`flow`, `only_stream` e `no_stream` não mudam essa base.

- `content` com `offset + depth` preserva `offset .. offset+depth-1`.
- Conteúdos relativos com `within`, com ou sem `distance`, usam um envelope
  contínuo a partir de um conteúdo anterior compatível; distâncias permanecem.
- Janelas sobrepostas ou adjacentes são unidas e offsets absolutos reajustados.
- Conteúdo negado não avança o cursor. Regras só com conteúdos negados
  conservam também o byte zero para evitar esvaziar um payload antes não vazio.
- HTTP/SMB/SSH com janelas finitas no payload bruto são convertidos para TCP
  com `flow:no_stream`; regras desses protocolos com `only_stream` são rejeitadas.
- Regras de cabeçalho e demais opções aceitas são mantidas.

São excluídos buffers de aplicação (`http.uri`, `file.data` etc.), outros
protocolos de aplicação, buscas sem limite finito, `endswith`, offsets negativos
e, por decisão de escopo, **`depth` sem `offset` e `startswith`**.
Também são excluídos `pcre`, `byte_test`, `byte_jump`, `byte_extract`, `byte_math`,
`isdataat`, `asn1` e `rpc` no payload; `dsize`, `stream_size`, `stream-event`,
`app-layer-event`, `app-layer-protocol`, `ipv4-csum`, `tcpv4-csum`, `udpv4-csum`,
`tcpv6-csum` e `udpv6-csum`.

## Limitações

Aceitação pelo algoritmo não comprova equivalência de detecção. O corte pode
alterar campos observados pelas regras, remontagem de fluxos e dependências.
Por exemplo, a SID 2069043 de transporte depende do produtor de flowbit
2069042, rejeitado pelo algoritmo.

O grupo IP não exige payload bruto nesta base. Seu summary indica `(nenhum)`;
os executores conservam o byte zero, pois um mapa sem intervalos desativa o
corte. Isso explica a redução do PCAP mesmo sem regras IP adaptadas.

O BPF aceita até 16 intervalos e payload de até 2048 bytes. Casos não suportados
podem passar sem corte, o que precisa ser compatibilizado com as regras adaptadas.
Veja as [condições dos experimentos](../experiments/README.md) e os
[testes de detecção](../tests/README.md).

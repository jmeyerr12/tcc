# Escopo atual do algoritmo

Este documento descreve o que esta implementado, nao uma retirada do grupo
de aplicacao do TCC. O foco e a adaptacao do conjunto de regras dos tres grupos.
Veja os [problemas do corte e suas implicacoes](LIMITACOES_DO_CORTE.md).

Os intervalos sao calculados sobre o **payload de cada pacote**. `flow`,
`only_stream` e `no_stream` nao mudam essa base. Os intervalos sao inclusivos;
nao se acrescenta um prefixo apenas para evitar copia.

## Tratamento atual

- Protocolos aceitos: `ip`, `ipv6`, `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`,
  `tcp-pkt`, `tcp-stream` e `pkthdr`.
- `content` com `offset + depth`: janela `offset .. offset+depth-1`.
- Conteudos relativos com `within`, com ou sem `distance`: envelope continuo
  a partir de um conteudo anterior compativel. Distancias relativas permanecem.
- Janelas sobrepostas/adjacentes sao unidas; offsets absolutos sao reajustados.
- Conteudo negado nao avanca o cursor. Regras somente com conteudos negados
  conservam tambem o byte zero para evitar esvaziar um payload antes nao vazio.
- Regras de header e opcoes restantes sao mantidas pelo algoritmo. Isso nao
  comprova equivalencia: campos alterados pelo corte e dependencias precisam
  de validacao no Suricata.

## Rejeitado pela implementacao atual

Protocolos de aplicacao no header (`http`, `smb`, `ssh` etc.) e buffers de
aplicacao sao excluidos. Conservar uma janela de conteudo nao garante o
reconhecimento do protocolo. Veja o [conjunto de aplicacao](../application-rules/README.md).

Tambem sao excluidos: buscas sem limite finito; `depth` sem `offset` e
`startswith` por decisao de escopo; `endswith`; offsets negativos; operacoes
como `pcre`, `byte_test`, `byte_jump`, `byte_extract`, `byte_math`, `isdataat`,
`asn1` e `rpc` no payload; `dsize`, `stream_size`, `stream-event`,
`app-layer-event` e `app-layer-protocol`.

O XDP aceita ate 16 intervalos e payloads de ate 2048 bytes. VLAN, fragmentos,
extensoes IPv6 e outros casos nao suportados passam sem corte; esse caminho
precisa ser compatibilizado com as regras adaptadas antes de validar o sistema.

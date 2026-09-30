# escopo atual do algoritmo

Este arquivo registra as decisoes atuais de escopo da implementacao.

## criterio geral

O algoritmo mantem regras de rede/transporte que nao dependem do payload e adapta buscas no payload bruto quando a regiao de busca pode ser delimitada por intervalos finitos suportados.

Os intervalos sao sempre calculados sobre o payload do pacote. Opcoes de
`flow`, incluindo `only_stream` e `no_stream`, e os protocolos `tcp-pkt` e
`tcp-stream` nao alteram a base usada no calculo.

Regras cujo protocolo no header e de aplicacao, como `http`, `dns`, `tls`,
`ssh` e `smb`, sao descartadas, mesmo com uma janela finita no payload bruto.
O reconhecimento do protocolo pode depender de bytes fora dessa janela.
Somente os protocolos de rede/transporte explicitamente aceitos pelo algoritmo
entram na adaptacao; protocolos desconhecidos tambem sao descartados.

Buffers especificos de aplicacao, como `http.response_body`, `http.header`, `dns.query`, `tls.certs` e `file.data`, continuam fora do escopo porque seus offsets pertencem a buffers construidos ou normalizados pelo parser do IDS, e nao diretamente ao payload bruto.

Por decisao de escopo, uma busca que use apenas `depth` tambem e descartada, mesmo sendo finita, porque representa uma busca a partir do inicio do payload ate um limite.

## regras tratadas

| caso | tratamento |
|---|---|
| regra de rede/transporte sem dependencia do payload | mantida sem alteracao |
| inspecao de `tcp.hdr`, `udp.hdr`, `ipv4.hdr`, `ipv6.hdr`, `icmpv4.hdr`, `icmpv6.hdr` | mantida sem alteracao |
| `content + offset + depth` | intervalo absoluto finito `offset .. offset+depth-1`; o `offset` pode ser reajustado apos os cortes |
| `content` relativo com `within` | intervalo relativo finito; `distance` implicito igual a zero |
| `content` relativo com `distance + within` | intervalo relativo finito; a cadeia e preservada por uma envoltoria continua |
| varios `content` encadeados com janelas relativas finitas | tratados enquanto cada dependencia relativa tiver um `content` anterior compativel e a cadeia tiver uma ancora suportada |
| opcoes que nao alteram a posicao do payload, como `nocase`, `fast_pattern`, `flow`, `threshold`, `metadata`, `reference` e `sid` | preservadas na regra |

## regras descartadas

| caso | motivo |
|---|---|
| `content + depth` sem `offset` | descartado por decisao de escopo; busca do inicio do payload ate um limite |
| `startswith` no payload | descartado por decisao de escopo |
| `content` sem modificador de intervalo | busca aberta no payload |
| `offset` sem `depth` | intervalo aberto ate o fim |
| `distance` sem `within` | intervalo relativo aberto ate o fim |
| `endswith` no payload | depende do fim do buffer |
| `offset` negativo | nao tratado atualmente |
| `pcre` | nao representado genericamente por intervalo estatico |
| `byte_test` | operacao de payload nao tratada |
| `byte_jump` | posicao pode depender do valor lido |
| `byte_extract` | pode gerar valores e posicoes dinamicas |
| `byte_math` | calculo dependente dos dados do pacote |
| `isdataat` | nao tratado atualmente |
| `asn1` e `rpc` | operacoes de payload nao tratadas |
| `dsize` | o tamanho pode mudar com o packet washing |
| `stream_size` | depende do tamanho do stream |
| `stream-event` | semantica fora do modelo de intervalos |
| `app-layer-event` | semantica de camada de aplicacao nao tratada |
| `app-layer-protocol` | semantica de camada de aplicacao nao tratada |
| protocolo de aplicacao no header, com ou sem busca finita no payload bruto | reconhecimento do protocolo nao preservado pelo modelo de intervalos |
| buffers de aplicacao, como `http.header`, `http.uri`, `http.response_body`, `dns.query`, `tls.sni`, `tls.certs`, `file.data` e `base64_data` | nao sao tratados como offsets do payload bruto |

## regra pratica para intervalos

Atualmente, para payload bruto:

- `offset + depth`: tratado
- `within`: tratado quando existe um `content` anterior compativel
- `distance + within`: tratado quando existe um `content` anterior compativel
- `depth` sozinho: descartado
- `startswith`: descartado
- `offset` sozinho: descartado
- `distance` sozinho: descartado
- `content` sem limite: descartado
- `endswith`: descartado

Essas regras de intervalo se aplicam aos protocolos de rede/transporte
suportados. Mencionar HTTP ou outro protocolo em `msg` ou `metadata` nao
altera a classificacao; declarar esse protocolo no header exclui a regra.

Conteudos negados nao avancam o cursor das buscas relativas. Para regras so
com conteudos negados no payload, preserva-se tambem o byte 0, evitando que
um payload curto nao vazio deixe de ser inspecionado apos o corte. Janelas
relativas cujo fim pode ficar negativo sao descartadas: o Suricata pode
sofrer wrap e pesquisar ate o fim do buffer, fora do modelo finito.

## observacao sobre protocolos de aplicacao

Uma regra como:

```text
alert http ... (content:"abc"; offset:100; depth:20; ...)
```

e descartada: conservar a janela `100-119` nao garante que o Suricata
reconheca HTTP. O calculo dos intervalos continua sendo por pacote; a exclusao
se deve a dependencia do identificador de protocolo.

Uma regra como:

```text
alert http ... (http.response_body; content:"abc"; offset:100; depth:20; ...)
```

continua descartada porque o `offset` e relativo ao buffer `http.response_body`, e nao ao payload bruto original.

Nao se amplia um intervalo para conservar um prefixo arbitrario. O suporte
a protocolos de aplicacao fica como trabalho futuro, dependente de uma
justificativa dos bytes necessarios e de validacao da deteccao.

Os quatro SIDs excluidos do conjunto de aplicacao estao preservados em
`application-rules/excluded-application.rules`. Os arquivos original/adaptado
contem somente os quatro SIDs restantes. Esse conjunto esta desabilitado nos
experimentos: tres regras nao inspecionam payload e a regra UDP restante
depende de um flowbit sem produtor. Veja `application-rules/README.md`.

## observacao sobre offset zero

`offset:0; depth:N;` continua tratado, porque existe um `offset` explicito e um limite `depth` explicito.

Se a decisao futura for descartar qualquer intervalo que comece no byte zero, inclusive `offset:0; depth:N;`, isso deve ser implementado como uma regra adicional de escopo.

## saida do algoritmo

O programa imprime apenas o resumo necessario para acompanhar a execucao:

- intervalos extraidos
- intervalos apos merge
- intervalos mesclados
- cortes finitos
- intervalos reajustados
- resumo do payload
- regras analisadas
- regras mantidas sem alteracao
- regras adaptadas
- regras descartadas

Nao sao mantidas classificacoes detalhadas por motivo de descarte no relatorio principal.



## Possível extensão: sticky buffers de aplicação

Algumas regras de protocolos de aplicação utilizam sticky buffers, como `http.response_body`, `http.header`, `dns.query` e `tls.certs`. Nesses casos, `offset`, `depth`, `distance` e `within` são relativos ao buffer construído pelo IDS, e não diretamente ao payload bruto do pacote.

Por esse motivo, a adaptação feita atualmente para payload bruto não pode ser aplicada diretamente a esses buffers. Ainda assim, existem algumas possibilidades sem modificar o packet washer:

1. **Manter a regra inalterada:** aceitar a regra somente quando o tráfego lavado já preservar informação suficiente para que o IDS reconstrua o sticky buffer original. Nesse caso, os valores de `offset`, `depth`, `distance` e `within` permanecem iguais.

2. **Tratar apenas casos com mapeamento direto:** em casos específicos onde seja possível determinar estaticamente a correspondência entre a posição no sticky buffer e a posição no payload bruto, o intervalo poderia ser convertido para o modelo atual e adaptado normalmente.

3. **Classificar como compatibilidade incerta:** identificar a regra e seu sticky buffer, mas não adaptá-la automaticamente quando não for possível garantir que o buffer reconstruído pelo IDS será equivalente após o packet washing.

Uma adaptação genérica que permita remover regiões internas de `http.response_body`, `dns.query`, `tls.certs` e buffers semelhantes exigiria conhecimento da estrutura do protocolo e possivelmente parsing, normalização ou reassembly. Isso provavelmente demandaria alterações também no packet washer e, por isso, pode ser considerado fora do escopo atual e deixado como trabalho futuro.

No escopo atual, tanto protocolos de aplicação no header quanto buffers de
aplicação ficam fora da adaptação automática, mesmo quando há intervalos
finitos explícitos. As possibilidades acima são extensões futuras.

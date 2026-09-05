# escopo atual do algoritmo

Este arquivo registra as decisoes atuais de escopo da implementacao.

## criterio geral

O algoritmo mantem regras que nao dependem do payload e adapta apenas buscas no payload bruto que tenham uma regiao de busca delimitada segundo os casos definidos abaixo.

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
| protocolos de aplicacao no header da regra, como `http`, `dns`, `tls`, `smtp` e `ftp` | fora do escopo atual |
| buffers de aplicacao, como `http.header`, `http.uri`, `dns.query`, `tls.sni`, `file.data` e `base64_data` | nao sao tratados como offsets do payload bruto |

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

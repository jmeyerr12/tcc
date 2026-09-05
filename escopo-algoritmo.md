# escopo atual do algoritmo

Este arquivo registra as decisoes atuais de escopo da implementacao.

## criterio geral

O algoritmo mantem regras de rede/transporte que nao dependem do payload e adapta buscas no payload bruto quando a regiao de busca pode ser delimitada por intervalos finitos suportados.

Regras cujo protocolo no header e de aplicacao, como `http`, `dns`, `tls`, `ssh` e `smb`, tambem podem ser analisadas. Elas so sao adaptadas quando o `content` atua sobre o payload bruto e usa um intervalo finito suportado.

Buffers especificos de aplicacao, como `http.response_body`, `http.header`, `dns.query`, `tls.certs` e `file.data`, continuam fora do escopo porque seus offsets pertencem a buffers construidos ou normalizados pelo parser do IDS, e nao diretamente ao payload bruto.

Por decisao de escopo, uma busca que use apenas `depth` tambem e descartada, mesmo sendo finita, porque representa uma busca a partir do inicio do payload ate um limite.

## regras tratadas

| caso | tratamento |
|---|---|
| regra de rede/transporte sem dependencia do payload | mantida sem alteracao |
| inspecao de `tcp.hdr`, `udp.hdr`, `ipv4.hdr`, `ipv6.hdr`, `icmpv4.hdr`, `icmpv6.hdr` | mantida sem alteracao |
| protocolo de aplicacao no header + `content` no payload bruto + `offset + depth` | adaptada como intervalo absoluto finito |
| protocolo de aplicacao no header + cadeia relativa finita no payload bruto | adaptada pelas mesmas regras de `distance` e `within` usadas no payload bruto |
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
| protocolo de aplicacao sem uma busca finita suportada no payload bruto | descartado |
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

As mesmas regras de intervalo sao usadas quando o protocolo declarado no header e de aplicacao, desde que nenhum sticky buffer ou buffer especifico de aplicacao esteja ativo.

## observacao sobre protocolos de aplicacao

Uma regra como:

```text
alert http ... (content:"abc"; offset:100; depth:20; ...)
```

pode entrar no tratamento atual porque o intervalo e calculado sobre o payload bruto.

Uma regra como:

```text
alert http ... (http.response_body; content:"abc"; offset:100; depth:20; ...)
```

continua descartada porque o `offset` e relativo ao buffer `http.response_body`, e nao ao payload bruto original.

A equivalencia semantica completa das regras de protocolo de aplicacao ainda deve ser validada experimentalmente, porque a deteccao do proprio protocolo de aplicacao pode depender dos bytes preservados pelo packet washing.

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

No escopo atual, regras de protocolos de aplicação podem ser adaptadas quando seus intervalos são definidos diretamente sobre o payload bruto. Regras que dependem de sticky buffers permanecem fora da adaptação automática.
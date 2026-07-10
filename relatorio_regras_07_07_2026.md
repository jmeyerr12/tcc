# Relatorio preliminar de classificacao de regras Snort para o MicroSec

## Objetivo

Este relatorio descreve a classificacao das regras do `snort3-community.rules` em relacao a compatibilidade com a implementacao atual do algoritmo de adaptacao do MicroSec (`alg.cpp`).

O objetivo nao foi afirmar que todas as regras descartadas sao impossiveis de adaptar, mas separar:

- regras ja suportadas pela implementacao atual;
- regras descartadas por nao serem seguras no modelo atual de adaptacao estatica;
- regras que podem ser tratadas futuramente com extensoes no `alg.cpp`.

## Visao geral da abordagem

A implementacao atual trabalha com adaptacao estatica baseada nas regras. Ou seja, o algoritmo analisa as opcoes da regra Snort e calcula intervalos de bytes que devem ser preservados, sem inspecionar dinamicamente cada pacote em busca dos padroes.

Por isso, regras com posicao explicita no payload sao trataveis pelo metodo atual. Ja regras cujo padrao pode ocorrer em qualquer posicao do payload nao podem ser preservadas com seguranca sem uma abordagem dinamica, pois seria necessario localizar o padrao no pacote antes de decidir quais bytes manter.

## Resultado geral

Foram analisadas 3917 regras do conjunto `snort3-community.rules`.

| Categoria | Quantidade | Interpretacao |
|---|---:|---|
| Incluidas automaticamente | 246 | Regras compativeis com a implementacao atual |
| Descartadas | 3477 | Regras nao seguras para inclusao automatica no metodo atual |
| Revisao manual | 194 | Regras potencialmente adaptaveis, mas que exigem extensoes ou decisao metodologica |

## Regras incluidas automaticamente

As 246 regras incluidas sao aquelas que a implementacao atual consegue tratar com maior seguranca.

| Tipo | Quantidade | Motivo da inclusao |
|---|---:|---|
| `behavior_header,payload_positioned` | 145 | Regras com criterio de cabecalho/fluxo e payload posicionado |
| `behavior_header` | 94 | Regras puramente baseadas em cabecalho, fluxo, flags ou metadados |
| `payload_positioned` | 4 | Regras com payload posicionado, sem depender de comportamento/cabecalho |
| `behavior_frequency,behavior_header` | 3 | Regras com criterio de frequencia e cabecalho |

As regras com payload posicionado usam principalmente `content` com `offset` e/ou `depth`. Esses campos permitem converter a regra para intervalos absolutos de bytes, que e exatamente o que o `alg.cpp` precisa para calcular cortes e ajustar offsets.

Exemplo conceitual:

```txt
content:"ABC"; offset:10; depth:3;
```

Essa regra permite inferir que o trecho relevante esta no intervalo iniciado em `10`, limitado por `depth`.

## Resultado da adaptacao pelo `alg.cpp`

Ao aplicar o `alg.cpp` sobre `microsec_candidate.rules`, o algoritmo encontrou os seguintes intervalos finais:

| Saida | Intervalos |
|---|---|
| `Merged` | `0-99`, `288-288` |
| `Cuts` | `100-287`, `289-1499` |
| `Adjusted` | `0-99`, `100-100` |

Isso significa que, para o conjunto candidato atual, o algoritmo preservou os bytes `0-99` e o byte `288`, removendo os demais trechos. Depois da remocao dos bytes `100-287`, o byte original `288` passa a ocupar a posicao `100`.

Foi observada uma alteracao concreta em regra adaptada:

```txt
offset 288
```

foi ajustado para:

```txt
offset 100
```

Esse comportamento e coerente com a remocao dos bytes anteriores ao offset original.

## Regras descartadas

As 3477 regras descartadas nao devem ser interpretadas como "impossiveis para sempre". Elas foram descartadas porque nao podem ser incluidas com seguranca na implementacao atual, que e estatica e baseada em intervalos inferidos a partir das regras.

O principal motivo de descarte foi a presenca de `content` sem ancora absoluta.

Exemplo:

```txt
content:"malware";
```

Nesse caso, o padrao pode aparecer em qualquer posicao do payload. Sem olhar o pacote real, o algoritmo nao consegue saber qual intervalo deve ser preservado. Para garantir a preservacao de forma estatica, seria necessario manter o payload inteiro, o que contraria o objetivo do packet washing.

Principais motivos encontrados entre as regras descartadas:

| Motivo | Ocorrencias aproximadas | Interpretacao |
|---|---:|---|
| `content` sem ancora absoluta | 3155 | Padrao pode estar em qualquer byte do payload |
| Cabecalho/fluxo junto de payload sem posicao segura | 3412 | A regra tem `flow`/cabecalho, mas ainda depende de busca arbitraria no payload |
| Buffer normalizado/camada de aplicacao | 1950 | Offset pode ser relativo a buffer reconstruido, nao ao pacote bruto |
| `pcre` sem ancora de intervalo | 1024 | Expressao regular pode varrer uma regiao indefinida |
| Operadores de payload nao suportados | 746 | Exigem semantica adicional no adaptador |

## Regras em revisao manual

As 194 regras em revisao manual sao as mais interessantes para evolucao do trabalho. Elas nao foram incluidas automaticamente, mas podem motivar proximas implementacoes no `alg.cpp`.

| Categoria | Quantidade | Possivel encaminhamento |
|---|---:|---|
| `unsupported_payload_operator` | 163 | Implementar suporte a operadores como `byte_test`, `byte_jump`, `isdataat` |
| `size_dependent_rule` | 14 | Definir se `dsize` e `stream_size` devem ser recalculados ou descartados |
| `relative_payload_position` | 11 | Implementar suporte a cadeias com `distance` e `within` |
| `normalized_buffer_rule` | 6 | Avaliar buffers como `file_data`, `http_uri`, `http_client_body` |

Operadores mais frequentes nas regras em revisao:

| Operador | Ocorrencias |
|---|---:|
| `byte_test` | 83 |
| `isdataat` | 47 |
| `file_data` | 47 |
| `dsize` | 13 |
| `distance` | 11 |
| `within` | 11 |
| `byte_jump` | 10 |
| `http_uri` | 2 |
| `http_client_body` | 2 |
| `byte_extract` | 2 |
| `stream_size` | 1 |

## Tipos de regras que ainda podem ser adaptados no `alg.cpp`

### 1. Regras com `distance` e `within`

Essas regras usam posicoes relativas entre varios `content`.

Exemplo:

```txt
content:"abc"; offset:0;
content:"def"; distance:0; within:10;
```

Elas podem ser adaptaveis quando a cadeia comeca em um `content` ancorado por `offset` ou `depth`. O `alg.cpp` ainda nao recalcula essa relacao relativa apos os cortes, por isso essas regras foram colocadas em revisao manual.

### 2. Regras com `dsize` e `stream_size`

Essas regras dependem do tamanho do payload ou do fluxo.

Exemplo:

```txt
dsize:8;
```

Como o packet washing remove bytes, o tamanho observado pelo IDS pode mudar. Portanto, essas regras exigem uma decisao: recalcular o valor apos a lavagem, ajustar a regra, ou remover a regra do conjunto.

### 3. Operadores `byte_test`, `byte_jump`, `byte_extract`

Esses operadores analisam valores em posicoes especificas ou calculadas do payload.

Eles podem ser adaptaveis, mas exigem parser e semantica adicionais. Em especial, `byte_jump` pode mudar a posicao de leitura das proximas verificacoes, o que torna a adaptacao mais complexa.

### 4. Buffers normalizados (`file_data`, `http_uri`, `http_client_body`)

Essas regras operam sobre buffers logicos reconstruidos pelo Snort, e nao necessariamente sobre o payload bruto do pacote.

Exemplo:

```txt
file_data;
content:"...";
```

Para adaptar essas regras corretamente, seria necessario entender a relacao entre o buffer normalizado e os bytes removidos pelo MicroSec. Por isso, elas nao foram incluidas automaticamente.

### 5. Regras com `pcre`

Regras com expressoes regulares podem ser adaptaveis apenas quando a regiao de busca for bem delimitada. Sem limite claro, a regex pode depender de qualquer parte do payload.

## Conclusao

A classificacao atual e propositalmente conservadora. Ela inclui apenas regras suportadas pela implementacao atual, descarta regras incompatíveis com a adaptacao estatica por intervalos e separa regras promissoras para evolucao futura.

Esse resultado mostra uma limitacao importante do metodo atual: ele funciona bem para regras com posicoes claras no payload e para regras de cabecalho/comportamento, mas nao cobre automaticamente regras que dependem de busca arbitraria, buffers normalizados, expressoes regulares ou operadores complexos de payload.

Como proximo passo, a evolucao mais natural do `alg.cpp` seria implementar suporte a `distance`/`within`, pois essas regras representam uma extensao direta do modelo de intervalos ja existente.

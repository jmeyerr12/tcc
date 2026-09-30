# Comparação entre o IDS com e sem o cortador

> Registro historico: os resultados de aplicacao abaixo usam o conjunto anterior
> de oito regras e o intervalo `4-183`. Quatro regras dependentes da identificacao
> de HTTP/SMB/SSH foram excluidas do escopo suportado; o cenario `application`
> esta desabilitado. Estes numeros nao validam equivalencia de deteccao nem
> descrevem o conjunto atual. Veja [situacao do conjunto](../application-rules/README.md).

## Objetivo

Comparar o desempenho do Suricata em dois modos:

- **Sem cortador (baseline):** os pacotes são entregues integralmente ao IDS.
- **Com cortador:** somente os intervalos necessários às regras são mantidos em
  cada pacote antes de sua entrega ao IDS.

Não são comparadas diferentes implementações do cortador.

## Configuração do experimento

- Tráfego: `CICIDS2017-Monday-mtu1500.pcap`.
- Taxa nominal: 5 Gbit/s.
- Duração: 10 segundos.
- Geração: duas instâncias do `tcpreplay`.
- IDS: Suricata com oito workers.
- Ambiente: interfaces `veth` na mesma máquina.
- Conjuntos de regras: aplicação, transporte e rede/IP.

## Resultados

| Regras | Modo | Tráfego gerado | Tráfego recebido pelo IDS | Pacotes no IDS | Perda de captura | Redução média do tamanho |
|---|---|---:|---:|---:|---:|---:|
| Aplicação | Sem cortador | 5.000,00 Mbit/s | 4.998,73 Mbit/s | 914.311,50 pps | 0,020765% | — |
| Aplicação | Com cortador | 4.993,49 Mbit/s | 1.079,03 Mbit/s | 913.562,88 pps | 0,000000% | 78,39% |
| Transporte | Sem cortador | 4.999,99 Mbit/s | 4.978,05 Mbit/s | 911.453,10 pps | 0,333340% | — |
| Transporte | Com cortador | 4.980,31 Mbit/s | 4.052,85 Mbit/s | 899.132,07 pps | 1,351740% | 17,50% |
| Rede/IP | Sem cortador | 4.998,58 Mbit/s | 4.499,71 Mbit/s | 843.791,40 pps | 7,711808% | — |
| Rede/IP | Com cortador | 4.999,99 Mbit/s | 423,31 Mbit/s | 792.916,80 pps | 13,295217% | 90,23% |

A redução do tráfego recebido pelo IDS no modo com cortador é esperada: ela
representa principalmente os bytes removidos dos pacotes. Por isso, essa coluna
não deve ser interpretada isoladamente como perda. A perda de captura e a taxa
de pacotes recebidos pelo IDS mostram se ele conseguiu acompanhar o tráfego.

## Comparação

- **Aplicação:** o cortador manteve praticamente a mesma taxa de pacotes do
  baseline, reduziu em 78,39% o tamanho médio dos pacotes e não apresentou perda
  de captura na execução medida.
- **Transporte:** o cortador reduziu somente 17,50% do tamanho médio. A perda de
  captura aumentou de 0,333340% para 1,351740%.
- **Rede/IP:** apesar da redução de 90,23% no tamanho médio, a perda aumentou de
  7,711808% para 13,295217%. A maioria dessas regras trabalha com cabeçalhos ou
  eventos do decoder, portanto o corte de payload não elimina seu custo por
  pacote.

## Conclusão preliminar

Na máquina utilizada, o melhor resultado do cortador ocorreu com as regras de
aplicação: houve grande redução do número de bytes sem redução relevante da
taxa de pacotes recebidos. Como o baseline também operou praticamente sem
perda, este ensaio demonstra a redução do tráfego entregue ao IDS, mas ainda
não demonstra aumento de sua capacidade máxima. Nos conjuntos de transporte e
rede/IP, a redução do número de bytes não resultou em menor perda de captura.
Assim, o efeito do cortador depende dos intervalos preservados e do tipo de
processamento exigido pelas regras.

Estes valores correspondem a uma execução por modo. A comparação final deve
usar várias repetições nas mesmas condições e apresentar média, dispersão e
intervalo de confiança. O teste também deve ser repetido em uma máquina com
maior capacidade de processamento para verificar quanto da perda observada foi
causada pela limitação do equipamento atual.

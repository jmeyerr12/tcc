# Resultados dos experimentos

## Rodada atual — 1 de outubro de 2026

Atualizacao com as 12 comparacoes executadas entre 11:53 e 11:59
(America/Sao_Paulo; os diretorios usam timestamps UTC `20261001T145313Z`
a `20261001T145854Z`). Sao quatro cargas por grupo, com uma execucao de
10 segundos por modo em cada ponto: 24 execucoes ate 5 Gbit/s.
Foram acrescentadas tres comparacoes aprovadas em 7,5 Gbit/s: aplicacao
(12:18), rede/IP (12:21) e o reteste de transporte (12:26), totalizando
**15 comparacoes incluidas e 30 execucoes**. Os horarios estao em
America/Sao_Paulo. Os tres grupos agora possuem uma comparacao aprovada no
criterio de carga de 7,5 Gbit/s. A primeira tentativa de transporte foi
reprovada e nao entra nesses totais.

Esta rodada usa os conjuntos completos aceitos pelo algoritmo, classificados
pelo cabecalho original e sem sobreposicao. Os logs do Suricata confirmam as
quantidades abaixo nos dois modos, sem regras com falha ou ignoradas.

| Grupo | Regras em cada modo | Adaptadas no payload | Mantidas sem alteracao | Reducao de bytes do PCAP |
|---|---:|---:|---:|---:|
| Aplicacao | 4 | 4 | 0 | 78,79% |
| Transporte | 1.005 | 71 | 934 | 17,27% |
| Rede/IP | 526 | 0 | 526 | 91,84% |
| Total | 1.535 | 75 | 1.460 | — |

Em rede/IP, as regras aceitas nao exigem intervalos de payload bruto; o
executor conserva o byte zero, porque zero entradas no mapa desativa o
corte XDP. A reducao de 91,84% corresponde ao PCAP preparado para esse caso.
Os resultados se aplicam ao recorte declarado do adaptador, que exclui,
entre outros casos, `depth` sem `offset` e `startswith` no payload.

## Metodo

Comparou-se o PCAP comum com regras originais aceitas ao mesmo PCAP previamente
cortado com as regras correspondentes adaptadas. O XDP permaneceu desligado
durante a medicao e o Suricata usou `-k none`.

- Maquina: Intel Core i7-1065G7, 4 nucleos e 8 CPUs logicas.
- Sistema: Linux 7.1.1-76070101-generic x86_64.
- Suricata 8.0.7 e tcpreplay 4.3.4.
- PCAP base: `CICIDS2017-Monday-supported.pcap`.
- Workers e afinidade de CPU: automaticos ate 5 Gbit/s; em 7,5 Gbit/s,
  5 workers nas CPUs `3,4,5,6,7` e 3 geradores nas CPUs `0,1,2`.
- Geradores: um nas cargas de 500 Mbit/s, 1 e 2 Gbit/s; dois em 5 Gbit/s.
- Ordem: original seguido de cortado, uma vez por ponto.

Nas cargas ate 5 Gbit/s, o alvo em Mbit/s do cortado foi multiplicado pela
proporcao de bytes do PCAP.
Isso aproxima a carga em pacotes, mas nao garante PPS identico em uma janela
de 10 segundos: o PPS enviado com corte ficou entre 0,0066% e 3,3511% menor
que o original. Por exemplo, IP a 500 Mbit/s enviou 92.847 contra 89.736 pps.
Nesses pontos, `target_pps=0` e `target_valid=n/a`: a verificacao de pelo menos
99% do PPS alvo, usada pelo script em 7,5 Gbit/s, nao foi aplicada.

A perda nas tabelas e a **perda de captura**, calculada por
`100 * kernel_drops / kernel_packets`. A reducao de bytes e calculada sobre
os arquivos PCAP, separadamente da perda de captura. Nao houve retries
`ENOBUFS`, pacotes com falha no tcpreplay ou descartes de interface registrados
nas 24 execucoes ate 5 Gbit/s. Pequenas diferencas positivas entre PPS no IDS e PPS enviado
podem incluir trafego adicional da interface; nao significam perda negativa.

## Resultados atuais — 500 Mbit/s a 5 Gbit/s

Cada carga abaixo aponta para seu `comparison.tsv` local. Os logs
`*mbps-original.log` e `*mbps-cut.log` no mesmo diretorio identificam os
resultados individuais, com `summary.tsv` e logs completos do Suricata.
PPS foi arredondado para inteiros apenas na apresentacao; os arquivos fonte
preservam as casas decimais.

### Aplicacao

| Carga / fonte | Mbit/s original / cortado | PPS original / cortado | PPS no IDS original / cortado | Perda original / cortado |
|---:|---:|---:|---:|---:|
| [500 Mbit/s](../experiments/results/precut_comparison_application_20261001T145313Z/comparison.tsv) | 499,99 / 106,05 | 92.847 / 90.469 | 92.851 / 90.469 | 0,000000% / 0,000000% |
| [1 Gbit/s](../experiments/results/precut_comparison_application_20261001T145344Z/comparison.tsv) | 1.000,00 / 212,10 | 180.652 / 179.671 | 180.656 / 179.672 | 0,000000% / 0,000000% |
| [2 Gbit/s](../experiments/results/precut_comparison_application_20261001T145415Z/comparison.tsv) | 2.000,00 / 424,21 | 361.197 / 359.322 | 361.104 / 359.322 | 0,026578% / 0,000000% |
| [5 Gbit/s](../experiments/results/precut_comparison_application_20261001T145445Z/comparison.tsv) | 4.999,98 / 1.060,52 | 897.652 / 896.545 | 897.287 / 896.268 | 0,041063% / 0,030885% |

### Transporte

| Carga / fonte | Mbit/s original / cortado | PPS original / cortado | PPS no IDS original / cortado | Perda original / cortado |
|---:|---:|---:|---:|---:|
| [500 Mbit/s](../experiments/results/precut_comparison_transport_20261001T145516Z/comparison.tsv) | 499,99 / 413,62 | 92.847 / 92.737 | 92.850 / 92.738 | 0,000000% / 0,000000% |
| [1 Gbit/s](../experiments/results/precut_comparison_transport_20261001T145548Z/comparison.tsv) | 999,99 / 827,26 | 180.652 / 180.601 | 180.655 / 180.601 | 0,000000% / 0,000000% |
| [2 Gbit/s](../experiments/results/precut_comparison_transport_20261001T145619Z/comparison.tsv) | 2.000,00 / 1.654,52 | 361.197 / 361.088 | 361.094 / 360.971 | 0,029568% / 0,032568% |
| [5 Gbit/s](../experiments/results/precut_comparison_transport_20261001T145650Z/comparison.tsv) | 4.999,98 / 4.136,28 | 897.652 / 897.593 | 897.265 / 897.142 | 0,043513% / 0,050257% |

### Rede/IP

| Carga / fonte | Mbit/s original / cortado | PPS original / cortado | PPS no IDS original / cortado | Perda original / cortado |
|---:|---:|---:|---:|---:|
| [500 Mbit/s](../experiments/results/precut_comparison_ip_20261001T145721Z/comparison.tsv) | 499,99 / 40,78 | 92.847 / 89.736 | 92.851 / 89.736 | 0,000000% / 0,000000% |
| [1 Gbit/s](../experiments/results/precut_comparison_ip_20261001T145752Z/comparison.tsv) | 1.000,00 / 81,56 | 180.652 / 179.256 | 180.654 / 179.256 | 0,000609% / 0,000000% |
| [2 Gbit/s](../experiments/results/precut_comparison_ip_20261001T145823Z/comparison.tsv) | 2.000,00 / 163,13 | 361.197 / 358.488 | 358.914 / 358.298 | 0,633083% / 0,053056% |
| [5 Gbit/s](../experiments/results/precut_comparison_ip_20261001T145854Z/comparison.tsv) | 4.999,98 / 407,84 | 897.652 / 896.063 | 630.562 / 633.556 | 29,754526% / 29,295612% |

## Resultados atuais — 7,5 Gbit/s aprovados

Somente as comparacoes com `target_valid=PASS` entram nesta tabela. O criterio
e atingir pelo menos **99% de 1.343.996 pps nos dois modos**. O gerador usa
controle por PPS, com agrupamento de 32 pacotes; a aprovacao avalia a carga
enviada, nao a ausencia de perda no IDS. Por isso, o resultado de IP e valido
como carga de 7,5 Gbit/s equivalente mesmo com perda de captura elevada.

| Grupo / fonte | Mbit/s original / cortado | PPS original / cortado | PPS no IDS original / cortado | Perda original / cortado | PPS alvo atingido original / cortado |
|---|---:|---:|---:|---:|---:|
| [Aplicacao](../experiments/results/precut_comparison_application_20261001T151824Z/comparison.tsv) | 7.458,67 / 1.589,73 | 1.340.644 / 1.343.988 | 1.340.290 / 1.343.988 | 0,026584% / 0,000000% | 99,7506% / 99,9994% |
| [Transporte](../experiments/results/precut_comparison_transport_20261001T152656Z/comparison.tsv) | 7.419,62 / 6.153,03 | 1.334.953 / 1.337.410 | 1.288.654 / 1.300.147 | 3,468457% / 2,786214% | 99,3272% / 99,5099% |
| [Rede/IP](../experiments/results/precut_comparison_ip_20261001T152126Z/comparison.tsv) | 7.422,21 / 611,70 | 1.335.345 / 1.343.989 | 752.806 / 785.923 | 43,624731% / 41,523166% | 99,3563% / 99,9995% |

**Transporte aprovado no reteste de 12:26.** O original atingiu 99,3272%
do PPS alvo e o cortado, 99,5099%. A primeira
[tentativa de 12:19](../experiments/results/precut_comparison_transport_20261001T151955Z/comparison.tsv)
registrou `FAIL`: 98,4166% do PPS alvo no original e 98,5414% no cortado.
Ela foi excluida da tabela de resultados aprovados por nao atingir 99% nos
dois modos; seus arquivos permanecem preservados para rastreabilidade.

## Leitura da rodada atual

- **Aplicacao:** nenhuma perda de captura em 500 Mbit/s e 1 Gbit/s nos dois
  modos. Em 2 Gbit/s, a perda passou de 0,026578% para zero; em 5 Gbit/s,
  de 0,041063% para 0,030885%. O corte reduziu as perdas observadas nesses
  pontos, mas nao as eliminou em 5 Gbit/s. Em 7,5 Gbit/s, na configuracao
  com afinidade de CPU, a perda passou de 0,026584% para zero, com ambos
  os modos aprovados no criterio de PPS.
- **Transporte:** nenhuma perda em 500 Mbit/s e 1 Gbit/s. O corte apresentou
  perdas ligeiramente maiores em 2 Gbit/s (0,029568% para 0,032568%) e
  5 Gbit/s (0,043513% para 0,050257%). No reteste aprovado de 7,5 Gbit/s,
  a perda passou de 3,468457% para 2,786214%, reducao de 0,682243 ponto
  percentual. O IDS recebeu 1.288.654,50 contra 1.300.146,80 pps.
  O corte apresentou menor perda nessa carga, mas nao nos pontos de 2 e
  5 Gbit/s; as medicoes ainda precisam de repeticoes.
- **Rede/IP:** em 2 Gbit/s, a perda passou de 0,633083% para 0,053056%,
  com PPS enviado 0,7501% menor no modo cortado. Em 5 Gbit/s, passou de
  29,754526% para 29,295612%, diferenca de 0,458914 ponto percentual;
  o IDS recebeu 630.562,50 contra 633.555,84 pps. A reducao de 91,84% dos bytes
  do PCAP nao eliminou a perda elevada de pacotes nessa carga. Em 7,5 Gbit/s,
  a perda passou de 43,624731% para 41,523166%, reducao de 2,101565 pontos
  percentuais. O IDS recebeu 752.806,20 contra 785.922,52 pps; os dois modos
  atingiram o criterio de carga, mas a perda permaneceu acima de 41%.

Sao observacoes de uma execucao por ponto, com pequenas diferencas de carga
e sem alternancia da ordem. Elas nao estabelecem significancia estatistica,
causalidade ou ganho geral de capacidade do IDS. Estes ensaios de desempenho
tambem nao verificam, por si so, equivalencia dos alertas. A mudanca de
workers e afinidade de CPU em 7,5 Gbit/s deve ser considerada ao comparar
essa carga com os pontos ate 5 Gbit/s.

## Historico — 7,5 Gbit/s com o recorte anterior

Os valores abaixo foram preservados do registro anterior e nao fazem parte
dos resultados atuais. Os tres grupos ja possuem novas comparacoes aprovadas
acima. Os ensaios historicos usaram 5 workers nas CPUs `3,4,5,6,7` e
3 geradores nas CPUs
`0,1,2`, configuracao diferente daquela usada ate 5 Gbit/s.
O alvo foi 1.343.996 pps; os dois modos atingiram pelo menos 99% desse alvo.
No PCAP antigo de IP, a reducao de bytes era 90,59%, contra 91,84% na rodada atual.

| Grupo | Mbit/s original / cortado | PPS original / cortado | PPS no IDS original / cortado | Perda original / cortado |
|---|---:|---:|---:|---:|
| [Aplicacao](../experiments/results/precut_comparison_application_20261001T013837Z/comparison.tsv) | 7.468,65 / 1.588,41 | 1.342.050 / 1.342.955 | 1.341.218 / 1.342.955 | 0,0623% / 0% |
| [Transporte](../experiments/results/precut_comparison_transport_20261001T015552Z/comparison.tsv) | 7.401,43 / 6.149,83 | 1.332.121 / 1.336.858 | 1.198.641 / 1.293.046 | 10,0203% / 3,2772% |
| [Rede/IP](../experiments/results/precut_comparison_ip_20261001T020026Z/comparison.tsv) | 7.471,62 / 705,03 | 1.342.474 / 1.342.920 | 1.014.644 / 994.176 | 24,4200% / 25,9691% |

## Reproducao

Com os conjuntos de regras congelados, prepare os PCAPs para esta versao:

```bash
make precut-tools
sudo ./experiments/prepare_pre_cut_pcaps.sh
sudo system76-power profile performance
```

Para reproduzir as cargas de 500 Mbit/s a 5 Gbit/s:

```bash
for group in application transport ip; do
  for rate in 500 1000 2000 5000; do
    sudo ./experiments/run_pre_cut_comparison.sh "$group" 10 "$rate"
  done
done
```

Para repetir as cargas de 7,5 Gbit/s, feche outros programas e execute cada
comando com um minuto de intervalo. Os tres grupos ja passaram no criterio
de carga; os comandos abaixo permitem realizar novas repeticoes:

```bash
sudo env REPLAY_CPUS=0,1,2 IDS_CPUS=3,4,5,6,7 IDS_THREADS=5 \
  ./experiments/run_pre_cut_comparison.sh application 10 7500

sleep 60

sudo env REPLAY_CPUS=0,1,2 IDS_CPUS=3,4,5,6,7 IDS_THREADS=5 \
  ./experiments/run_pre_cut_comparison.sh transport 10 7500

sleep 60

sudo env REPLAY_CPUS=0,1,2 IDS_CPUS=3,4,5,6,7 IDS_THREADS=5 \
  ./experiments/run_pre_cut_comparison.sh ip 10 7500
```

Para a rodada final, realizar ao menos cinco repeticoes por ponto, alternando
os modos e mantendo a configuracao. O loop acima reproduz uma unica passagem,
sempre com original antes de cortado. Nao misturar as novas repeticoes com os
resultados historicos de outros conjuntos de regras.

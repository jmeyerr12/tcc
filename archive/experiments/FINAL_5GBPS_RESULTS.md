# Consolidacao preliminar a 5 Gbit/s

> Registro historico: os resultados de aplicacao abaixo usam o conjunto anterior
> de oito regras e o intervalo `4-183`. Quatro regras dependentes da identificacao
> de HTTP/SMB/SSH foram excluidas do escopo suportado; o cenario `application`
> esta desabilitado. Estes numeros nao validam equivalencia de deteccao nem
> descrevem o conjunto atual. Veja [situacao do conjunto](../../application-rules/README.md).

Comparacao dos tres conjuntos com o PCAP normalizado, duracao de 10 segundos e
dois geradores. Os valores abaixo sao de uma repeticao por modo; repeticoes
adicionais ainda sao necessarias para media, dispersao e intervalo de confianca.

| Regras | Baseline real | Cutter real | Baseline IDS (pps) | Cutter IDS (pps) | Reducao media do tamanho | Perda baseline | Perda cutter |
|---|---:|---:|---:|---:|---:|---:|---:|
| Aplicacao | 5.000,00 Mbit/s | 4.993,49 Mbit/s | 914.311,50 | 913.562,88 | 78,39% | 0,020765% | 0,000000% |
| Transporte | 4.999,99 Mbit/s | 4.980,31 Mbit/s | 911.453,10 | 899.132,07 | 17,50% | 0,333340% | 1,351740% |
| Rede/IP | 4.998,58 Mbit/s | 4.999,99 Mbit/s | 843.791,40 | 792.916,80 | 90,23% | 7,711808% | 13,295217% |

`Reducao media do tamanho` compara bytes por pacote enviado com bytes por
pacote efetivamente decodificado. Ela separa, na medida possivel, o efeito do
corte da perda de pacotes. A reducao bruta registrada nos `summary.tsv` tambem
inclui bytes ausentes por perda de captura.

## Interpretacao

- **Aplicacao:** melhor caso. O cortador manteve throughput e pps do baseline,
  reduziu 78,39% do tamanho medio e nao apresentou perda de captura.
- **Transporte:** o throughput externo foi mantido, mas apenas 17,50% do
  tamanho medio foi removido e a perda aumentou em 1,0184 ponto percentual.
- **Rede/IP:** embora o tamanho medio tenha caido 90,23%, a perda aumentou em
  5,5834 pontos percentuais. Quase todas as regras desse conjunto tratam
  headers/eventos do decoder, e nao payload; cortar bytes nao elimina esse
  custo por pacote.

## Conclusao

O beneficio do cortador depende do tipo de regra e nao pode ser inferido apenas
da porcentagem de bytes removidos. No notebook usado na bancada, o resultado e
positivo para aplicacao, neutro ou negativo para transporte e negativo para o
conjunto de rede/IP na metrica de perda de captura.

O alvo de 10 Gbit/s nao deve ser usado como resultado de capacidade desta
bancada: ate o baseline saturou abaixo dele. Os resultados comparaveis e
efetivamente sustentados estao em 5 Gbit/s.

## Relatorios detalhados

- `COMPARISON_RESULTS.md`: aplicacao e evolucao das otimizacoes;
- `TRANSPORT_RESULTS.md`: transporte antes e depois do caminho rapido;
- `IP_RESULTS.md`: rede/IP, separacao entre corte e perda e estatisticas do
  decoder.

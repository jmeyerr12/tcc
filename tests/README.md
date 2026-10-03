# Testes

Execute na raiz de `tcc`:

```bash
make test
```

Sem privilégios, verifica intervalos, adaptação de offsets, escopo, conversão
de protocolos, cobertura e reprodução dos três grupos, além da taxa de replay.
Os testes do analisador ficam em `analisador/tests/` e usam UBSan no C++.

## Comparação de alertas

```bash
sudo python3 tests/compare_alerts.py
```

Gera 66 pacotes sintéticos positivos e negativos, executa o cortador real via
`BPF_PROG_TEST_RUN` e compara alertas do Suricata por SID e conexão, usando
os três conjuntos completos. Requer as dependências dos
[experimentos](../experiments/README.md).

São esperados, em cada modo, 6 alertas de aplicação (SIDs 2008605 e 2009477),
6 de transporte (2008414 e 2003155) e 3 de IP (2404300), sem alertas nos
controles negativos. Horários de emissão podem diferir. PCAPs, regras, logs
e `comparison.tsv` ficam em `experiments/results/alerts_*`.

Para comparar com uma transformação de referência, sem privilégios:

```bash
python3 tests/compare_alerts.py --offline
```

O modo offline verifica os alertas no Suricata, mas não executa o XDP.
Esses casos cobrem cinco SIDs; não certificam toda a semântica dos conjuntos
nem desempenho sob carga.

`wash_pcap.cpp` executa o BPF sobre PCAPs e verifica payload, comprimentos,
cabeçalhos e preservação dos valores de checksum. Também é usado para preparar
as capturas dos experimentos; compile com `make precut-tools`.

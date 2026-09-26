# Primeiro teste end-to-end

Execute os comandos na raiz do projeto.

O teste requer:

- g++;
- clang;
- libbpf/libelf;
- Suricata;
- permissão para carregar programas BPF (`sudo`).

O kernel precisa suportar os helpers utilizados pelo washer (Linux >= 5.18).

O teste utiliza a regra real SID **2008414**, `ET SCAN Cisco Torch TFTP Scan`.

São gerados dois frames Ethernet/IPv4/UDP com checksums válidos:

- um pacote positivo;
- um pacote negativo.

O pacote positivo contém `Rand0mSTRING\0netascii` no offset original `2`.
Após a compactação do payload, a regra adaptada procura o mesmo conteúdo no
offset `1`, mantendo `depth:21`.

## Preparar

```bash
make

mkdir -p \
  /tmp/tcc-final-e2e/original-log \
  /tmp/tcc-final-e2e/washed-log

g++ -std=c++11 -Wall -Wextra -pedantic \
  tests/make_test_pcap.cpp \
  -o /tmp/tcc-final-e2e/make_test_pcap

g++ -std=c++11 -Wall -Wextra -pedantic \
  tests/wash_pcap.cpp \
  -lbpf -lelf -lz \
  -o /tmp/tcc-final-e2e/wash_pcap

/tmp/tcc-final-e2e/make_test_pcap \
  /tmp/tcc-final-e2e/original.pcap

rg 'sid:2008414;' suricata.rules \
  > /tmp/tcc-final-e2e/original.rules

rg 'sid:2008414;' suricata-adapted.rules \
  > /tmp/tcc-final-e2e/adapted.rules
```

## Executar o XDP real

```bash
sudo /tmp/tcc-final-e2e/wash_pcap af_xdp_kern.o suricata-summary.txt \
  /tmp/tcc-final-e2e/original.pcap /tmp/tcc-final-e2e/washed.pcap
```

O executor lê **Merged** do resumo, configura os dois mapas e executa cada
frame com BPF_PROG_TEST_RUN, sem anexar a uma interface. Não use **Adjusted**
nos mapas. Não misture regras e resumos gerados para conjuntos diferentes.
Resultado esperado: `PASS: 2 packets, 484 -> 258 bytes`.

## Comparar os alertas

Use diretórios de log vazios; o Suricata pode acrescentar resultados a logs
anteriores. Estes comandos usam uma configuração mínima apenas para o ensaio.

```bash
suricata -c /dev/null --runmode single \
  -r /tmp/tcc-final-e2e/original.pcap -S /tmp/tcc-final-e2e/original.rules \
  -l /tmp/tcc-final-e2e/original-log \
  --set vars.address-groups.HOME_NET=10.0.0.0/8 \
  --set vars.address-groups.EXTERNAL_NET=any \
  --set classification-file=/dev/null --set reference-config-file=/dev/null \
  --set threshold-file=/dev/null --set outputs.0=fast \
  --set outputs.0.fast.enabled=yes --set outputs.0.fast.filename=fast.log

suricata -c /dev/null --runmode single \
  -r /tmp/tcc-final-e2e/washed.pcap -S /tmp/tcc-final-e2e/adapted.rules \
  -l /tmp/tcc-final-e2e/washed-log \
  --set vars.address-groups.HOME_NET=10.0.0.0/8 \
  --set vars.address-groups.EXTERNAL_NET=any \
  --set classification-file=/dev/null --set reference-config-file=/dev/null \
  --set threshold-file=/dev/null --set outputs.0=fast \
  --set outputs.0.fast.enabled=yes --set outputs.0.fast.filename=fast.log

diff -u /tmp/tcc-final-e2e/original-log/fast.log /tmp/tcc-final-e2e/washed-log/fast.log
```

Esperado: logs iguais, com um alerta SID 2008414 para a porta de origem
12345 e nenhum para o controle negativo de porta 12346. Há também os
artefatos já existentes em `tests/e2e/sid-2008414/`.

## Testes unitários

```bash
g++ -std=c++11 -Wall -Wextra -pedantic -fsanitize=undefined \
  -fno-sanitize-recover=all -g -I. \
  tests/test_algorithm.cpp algorithm.cpp parser.cpp -o /tmp/tcc-test-algorithm
/tmp/tcc-test-algorithm
```

## Limites do ensaio

- O executor aceita PCAP clássico little-endian, Ethernet/IPv4 sem opções,
  TCP/UDP não fragmentado, checksums válidos e payload de até 2048 bytes.
- Comprimentos e checksums dos headers são atualizados; os demais campos
  são comparados byte a byte. Um teste não comprova equivalência universal.
- O washer deixa alguns formatos fora do escopo passarem sem corte. Não
  use offsets compactados para interpretar esses pacotes como se fossem lavados.
- A SID 2069043 depende do flowbit `ET.IKE.MS_Sec_VID`, cujo produtor
  SID 2069042 foi descartado. Essa regra não serve como teste isolado de
  equivalência no conjunto final; a SID 2008414 não tem essa dependência.

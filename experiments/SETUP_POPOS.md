# Preparação e execução dos experimentos no Pop!_OS

Este guia prepara uma instalação nova do Pop!_OS para comparar o Suricata sem
o cortador (baseline) e com o cortador XDP.

## 1. Clonar o projeto e transferir o PCAP

Os scripts e relatórios estão versionados na branch `experiments`. No notebook
Ryzen, clone essa branch:

```bash
mkdir -p /home/meyer/d
cd /home/meyer/d
git clone --branch experiments --single-branch \
  https://github.com/jmeyerr12/tcc.git
```

Os PCAPs e resultados são ignorados pelo Git devido ao tamanho. Para transferir
o PCAP pela rede local, instale e inicie o SSH no Ryzen:

```bash
sudo apt update
sudo apt install -y openssh-server rsync
sudo systemctl enable --now ssh
hostname -I
```

No notebook Intel, substitua o endereço abaixo pelo IP do Ryzen:

```bash
RYZEN_IP=192.168.0.100

scp /home/meyer/d/tcc/experiments/pcaps/CICIDS2017-Monday-mtu1500.pcap \
  meyer@"${RYZEN_IP}":/home/meyer/d/tcc/experiments/pcaps/
```

Se o usuário ou o caminho forem diferentes no Ryzen, ajuste o destino do
`scp` e use esse mesmo caminho nos comandos seguintes.

## 2. Instalar as dependências

No Ryzen:

```bash
sudo apt update
sudo apt install -y \
  software-properties-common \
  build-essential make git \
  clang llvm \
  python3 gawk ripgrep \
  libbpf-dev libelf-dev zlib1g-dev linux-libc-dev \
  linux-tools-common bpftool \
  iproute2 ethtool tcpreplay rsync

sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```

O PPA estável é usado para obter a mesma série atual do Suricata. O notebook
Intel executou o Suricata 8.0.7.

O serviço instalado pelo pacote não deve disputar a interface com os scripts:

```bash
sudo systemctl disable --now suricata
```

## 3. Conferir o ambiente

```bash
cd /home/meyer/d/tcc

uname -a
lscpu
suricata --build-info | head -n 5
tcpreplay --version | head -n 2
clang --version | head -n 1
bpftool version

command -v suricata
command -v tcpreplay
command -v ethtool
command -v bpftool
```

O kernel precisa ser Linux 5.18 ou superior. Confirme também que o PCAP foi
copiado integralmente:

```bash
sha256sum experiments/pcaps/CICIDS2017-Monday-mtu1500.pcap
```

Hash esperado:

```text
a652a6dfafa1312f3f9d7fcb01cf4ec045826d1a91a4b38da346be4df66225d6
```

## 4. Compilar

```bash
cd /home/meyer/d/tcc
chmod +x experiments/*.sh
make clean
make -j"$(nproc)"
ls -lh alg af_xdp_kern.o
```

## 5. Validar o XDP antes do experimento

Prepare as interfaces virtuais:

```bash
sudo ./experiments/setup_veth.sh up
```

Carregue o cortador com o menor conjunto de intervalos:

```bash
sudo ./experiments/setup_cutter.sh on application
sudo ./experiments/setup_cutter.sh status
```

Se aparecer `prog/xdp` na interface `tcc-ids`, o kernel aceitou e anexou o
programa. Faça então um ensaio curto:

```bash
sudo ./experiments/run_cutter_once.sh application 500 10 1
sudo ./experiments/setup_cutter.sh off
sudo ./experiments/run_baseline_once.sh application 500 10 1
```

Não continue para 5 Gbit/s se algum desses comandos falhar.

## 6. Primeira comparação no Ryzen: 5 Gbit/s

Mantenha o notebook conectado à tomada, selecione o perfil de alto desempenho
do Pop!_OS e feche outros programas. Recrie a `veth` antes da bateria:

```bash
cd /home/meyer/d/tcc
sudo ./experiments/setup_veth.sh up
```

### Aplicação

```bash
sudo ./experiments/run_baseline_once.sh application 5000 10 2
sudo ./experiments/setup_cutter.sh on application
sudo ./experiments/run_cutter_once.sh application 5000 10 2
sudo ./experiments/setup_cutter.sh off
```

### Transporte

```bash
sudo ./experiments/run_baseline_once.sh transport 5000 10 2
sudo ./experiments/setup_cutter.sh on transport
sudo ./experiments/run_cutter_once.sh transport 5000 10 2
sudo ./experiments/setup_cutter.sh off
```

### Rede/IP

```bash
sudo ./experiments/run_baseline_once.sh ip 5000 10 2
sudo ./experiments/setup_cutter.sh on ip
sudo ./experiments/run_cutter_once.sh ip 5000 10 2
sudo ./experiments/setup_cutter.sh off
```

Cada comando informa o diretório de resultado. Preserve os seis diretórios e
compare os respectivos arquivos `summary.tsv`.

## 7. Varredura completa

Somente depois de validar os ensaios de 5 Gbit/s, execute as taxas de 500
Mbit/s, 1, 2, 5 e 10 Gbit/s:

```bash
sudo ./experiments/run_baseline_sweep.sh application 10
sudo ./experiments/run_cutter_sweep.sh application 10

sudo ./experiments/run_baseline_sweep.sh transport 10
sudo ./experiments/run_cutter_sweep.sh transport 10

sudo ./experiments/run_baseline_sweep.sh ip 10
sudo ./experiments/run_cutter_sweep.sh ip 10
```

Os scripts de varredura geram um `summary.tsv` consolidado para cada modo e
conjunto de regras.

## 8. Repetições para o resultado final

Uma única execução serve para validar a bancada, mas não para o resultado
final. Depois de confirmar que tudo funciona, repita cada par baseline/cortador
pelo menos cinco vezes nas mesmas condições. Registre também:

```bash
uname -a
lscpu
suricata --build-info
tcpreplay --version
bpftool version
```

Não misture, na mesma tabela estatística, execuções realizadas em máquinas ou
versões de software diferentes.

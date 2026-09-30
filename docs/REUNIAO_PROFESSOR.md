# Resultados e decisões para a reunião

**Foco do TCC:** o algoritmo que adapta o conjunto de regras e define os bytes
a conservar. Avaliar a preservação da detecção no escopo suportado e comparar
o Suricata sem e com cortador, usando um PCAP genérico de Internet, os grupos
de **aplicação, transporte e rede/IP**, nas cargas de 500 Mb/s, 1, 2, 5 e
10 Gb/s. A prioridade é fechar o escopo e concluir os experimentos.

## Resultados preliminares

Bancada local com gerador, veth, XDP e Suricata na mesma máquina. PCAP
`CICIDS2017-Monday-mtu1500.pcap`; uma execução de 10 segundos por configuração
na tabela. A ordem dos pares é **sem cortador / com cortador**.

| Grupo | Alvo (Mb/s) | Taxa real enviada (Mb/s) | Perda de captura | Redução estimada do tamanho |
|---|---:|---:|---:|---:|
| Aplicação* | 500 | 499,99 / 499,99 | 0% / 0% | 77,81% |
| Aplicação* | 1.000 | 1.000,00 / 1.000,00 | 0% / 0% | 78,29% |
| Aplicação* | 2.000 | 2.000,00 / 1.998,08 | 0% / 0% | 78,29% |
| Aplicação* | 5.000 | 5.000,00 / 4.993,49 | 0,02% / 0% | 78,39% |
| Transporte | 5.000 | 4.999,99 / 4.980,31 | 0,33% / 1,35% | 17,50% |
| Rede/IP | 5.000 | 4.998,58 / 4.999,99 | 7,71% / 13,30% | 90,23% |

*Aplicação: conjunto anterior à exclusão das regras HTTP/SMB/SSH, atualmente
suspenso. Esses números não comprovam preservação da detecção. A redução de
tamanho é estimada; perdas podem alterar a distribuição dos pacotes recebidos.

No alvo de 10 Gb/s, com aplicação e quatro geradores, as taxas foram
8,36 Gb/s sem corte e 3,75 Gb/s com corte: a carga não foi atingida.
Nos testes Intel **sem IDS**, o caminho com corte atingiu 8,62 Gb/s com três
geradores e caiu para 5,67 Gb/s com quatro, com muitos retries `ENOBUFS`.
Isso evidencia limitação da bancada com XDP/veth, mas não separa o custo de
cópia/checksum do custo desse caminho de rede.

**Leitura atual:** houve redução de bytes, mas ainda não há demonstração de
ganho consistente de capacidade do IDS. Em transporte e IP, a perda de captura
foi maior com corte nessa execução. Faltam repetições para avaliar a variação.

## Limitações que afetam a interpretação

- **Aplicação:** remover `GET ` pode impedir o reconhecimento HTTP mesmo
  preservando o conteúdo da regra. Cabeçalhos de aplicação não têm formato
  e tamanho únicos. Essas regras estão excluídas da implementação atual;
  **o grupo de aplicação continua no objetivo** e seu conjunto precisa ser revisto.
- **Cortador: não é só VLAN.** Fragmentos IP, extensões IPv6 e payloads acima
  de 2.048 bytes também podem passar intactos. Nesses casos, offsets adaptados
  podem apontar para bytes errados. Além disso, o corte altera comprimentos
  e checksums, o que afeta regras que inspecionam esses campos.
- **Captura:** o ajuste para MTU 1500 encurtou 48.014 segmentos TCP sem
  resegmentá-los. O baseline já recebe essa carga modificada.

A [lista de limitações relevantes](LIMITACOES_DO_CORTE.md) detalha esses
pontos e distingue os casos demonstrados do alcance sobre os conjuntos atuais.

## Decisões propostas

1. **Escopo do adaptador:** definir regras e formatos suportados nos três
   grupos, incluindo aplicação; selecionar regras representativas e suas
   dependências, verificando a preservação dos alertas. Registrar exclusões,
   sem exigir uma implementação genérica para todos os protocolos.
2. **Bancada:** continuar localmente ou usar equipamento do laboratório?
   O MicroSec usou gerador separado e rede de 10 Gb/s. Os dois notebooks
   disponíveis não têm Ethernet; separá-los exige interfaces adequadas.
   Trocar apenas de notebook não garante eliminar o gargalo.
3. **PCAP:** manter a captura modificada, declarando a limitação, ou escolher
   outra captura adequada ao escopo? Usar a mesma nos dois modos.
4. **Fechamento:** fixar a configuração e realizar ao menos cinco repetições
   por ponto. Comparar perdas sob taxas reais equivalentes e registrar alvos
   não atingidos. Otimização pontual ou PCAP previamente cortado ficam como
   alternativas, caso necessárias, não como novos pré-requisitos gerais.

Fontes: [ensaios de aplicação](../archive/experiments/COMPARISON_RESULTS.md),
[comparação a 5 Gb/s](../archive/experiments/FINAL_5GBPS_RESULTS.md) e logs
locais em `experiments/results/`. Os relatórios antigos preservam as conclusões
da época; este resumo incorpora as limitações identificadas posteriormente.

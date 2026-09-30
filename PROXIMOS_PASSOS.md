# Proximos passos: experimentos

**Foco:** o algoritmo de adaptacao do conjunto de regras. Avaliar
**aplicacao, transporte e rede/IP**, preservando a deteccao no escopo declarado
e medindo reducao de bytes e desempenho. Aplicacao nao foi retirada do plano.
Os [problemas identificados](docs/LIMITACOES_DO_CORTE.md) delimitam o que
precisa ser garantido ou excluido, sem exigir suporte generico a todo protocolo.

1. **Aproveitar os ensaios ja realizados.** Manter os resultados como piloto
   e referencia. Fechar os conjuntos dos tres grupos e as condicoes suportadas.
   O conjunto atual de aplicacao precisa ser revisto antes de reabilitar seu
   cenario: rejeitar regras incompativeis nao significa abandonar a categoria.
   Verificar dependencias e equivalencia de alertas em casos que exercitem as
   regras selecionadas; registrar regras aceitas e excluidas. Congelar essa
   versao, corrigindo apenas o que impeca ou invalide a rodada.
2. **Escolher a bancada.** O caminho XDP/veth ja limitou o gerador sem IDS.
   Fazer uma rodada curta de capacidade com os conjuntos escolhidos e configuracao
   fixa de CPUs e geradores. Se limitar as cargas desejadas, priorizar
   gerador em outra maquina, com rede adequada, antes de novas otimizacoes.
   Trocar apenas o notebook e uma alternativa a medir, sem garantia de resolver.
3. **Rodar a comparacao final.** Mesmo PCAP generico de Internet e mesmos SIDs
   nos dois modos, com offsets adaptados no cortador. Alvos: **500 Mb/s, 1, 2,
   5 e 10 Gb/s**. Fixar CPUs, geradores e workers, aquecer, alternar os modos e fazer ao
   menos cinco repeticoes. Taxa nao atingida e resultado da bancada; comparar
   perdas sob cargas reais equivalentes.
4. **Fechar os resultados.** Consolidar taxas reais e recebidas pelo IDS em
   Mb/s e pps, perdas, reducao de bytes separada da perda e retries. Apresentar
   dispersao e intervalos de confianca. O cortador pode melhorar, empatar ou
   piorar: a conclusao deve refletir as medicoes desta versao e desta carga.

**Somente se necessario:** investigar uma otimizacao pontual com gargalo
medido. PCAP previamente cortado e um experimento complementar opcional,
nao uma condicao para concluir a comparacao principal.

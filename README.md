# Tamplate Contador de Pacotes TCP/SYN e UDP/NEW
SYN/TCP e UDP/NEW basicamente são pacotes de abertura de novas conexões, cada tipo de seu protocolo.
Contando eles é possível se ter um panorama geral de quantidade de conexões TCP e UDP em PPS e Bytes.

Em cenários onde se usa CCR2216 com Offload corretamente configurado, os pacotes de abertura são basicamente os únicos pacotes que "sobem" para a CPU antes da rota ser instalada no hardware. POR ISSO, é importante contabiliza-los.

Também é possivel pegar ataques DDoS do tipo SYN Flood e qualquer amplificação UDP (53 e 123 por exemplo)

O Tamplate é feito para Zabbix 7 e cria uma Dashboard para o equipamento com os dados analisados. DICA: Compare o gráfico de UDP/PPS com o grafico de CPU de seu Mikrotik e veja exatamente quando se teve DDoS.

### PASSO A PASSO:
## 1 - Habilitar uma comunidade SNMP com permissão de escrita 
(IMPORTANTE LIMITAR ao IP do Zabbix)

## 2 - Criar o Script Conforme abaixo:
Use o nome que quiser, eu chamo de "get_counters_tcp_udp_json"
# Script RouterOS:
```
:local output "{"
:local first true

# Lista exata dos comentarios
:local listaRegras {"MONITOR_TCP_SYN_COUNT"; "MONITOR_UDP_NEW_COUNT"}

:foreach nomeRegra in=$listaRegras do={
    # Busca os IDs. Isso retorna uma lista/array.
    :local foundIDs [/ip firewall filter find comment=$nomeRegra]
    
    # Verifica se a lista nao esta vazia
    :if ([:len $foundIDs] > 0) do={
        
        #Pegamos apenas o primeiro ID da lista para garantir
        :local singleID [:pick $foundIDs 0]
        
        # Inicializa variaveis para evitar erro
        :local packets 0
        :local bytes 0
        
        # Tenta pegar os valores
        :do {
            :set packets [/ip firewall filter get $singleID packets]
            :set bytes   [/ip firewall filter get $singleID bytes]
        } on-error={
            :put ("Erro ao ler dados da regra: " . $nomeRegra)
        }
        
        # Logica da virgula
        :if ($first = false) do={ :set output ($output . ",") }
        :set first false
        
        # Monta o JSON
        :set output ($output . "\"" . $nomeRegra . "\": {\"packets\": " . $packets . ", \"bytes\": " . $bytes . "}")
        
    } else={
        # Debug: Se nao achar a regra, avisa no terminal para voce saber
        :put ("AVISO: Nao encontrei nenhuma regra com o comentario: " . $nomeRegra)
    }
}

:set output ($output . "}")

# Imprime o JSON final
:put $output
```
Para testar se deu boa, pode rodar direto no terminal do mikrotik: ```/system/script/run get_counters_syn_new_json```
verá um resultado como: <br>
```{"MONITOR_TCP_SYN_COUNT": {"packets": 708555894, "bytes": 43545004564},"MONITOR_UDP_NEW_COUNT": {"packets": 32772666966, "bytes": 4195821380659}```


## 3 - Identificar o correto ID do Script com SNMP Walk:
snmpwalk -v2c -c comunity <ip> 1.3.6.1.4.1.14988.1.1.8.1.1.2

## 4 - Substituir na macro {$IDSCRIPT} pelo ID correspondente ao adicionar o script no Host. 
(pode criar o item macro no host mesmo) e usar a entrada "{$IDSCRIPT}" apontando para o value X (numero encontrado do script).

Em geral segue a lógica de:
1.3.6.1.4.1.14988.1.1.8.1.1.2.1 = primeiro script do mikrotik <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.2 = segundo script <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.3 = terceiro, e asim por diante.

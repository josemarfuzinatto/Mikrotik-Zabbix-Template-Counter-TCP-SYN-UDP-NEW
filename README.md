## Português
# Template Contador de Pacotes TCP/SYN e UDP/NEW
SYN/TCP e UDP/NEW basicamente são pacotes de abertura de novas conexões, cada tipo de seu protocolo.

Contando eles é possível se ter um panorama geral de quantidade de conexões TCP e UDP em PPS e Bytes.

Em cenários onde se usa CCR2216 com Offload corretamente configurado, os pacotes de abertura são basicamente os únicos pacotes que "sobem" para a CPU antes da rota ser instalada no hardware. POR ISSO, é importante contabiliza-los.

Também é possivel pegar ataques DDoS do tipo SYN Flood e qualquer amplificação UDP (53 e 123 por exemplo)

O Template é feito para Zabbix 7 e cria uma Dashboard para o equipamento com os dados analisados. DICA: Compare o gráfico de UDP/PPS com o grafico de CPU de seu Mikrotik e veja exatamente quando se teve DDoS.

### PASSO A PASSO:
## 1 - Habilitar uma comunidade SNMP com permissão de escrita 
(IMPORTANTE LIMITAR ao IP do Zabbix)
```
/snmp community
add addresses=100.100.100.50/32 name=zbx_wr1te write-access=yes
/snmp
set contact=xxx@exemplo.com.br enabled=yes location=Chapeco-SC
``` 
Substitua ```100.100.100.50/32``` pelo IP do seu Zabbix.

## 2 - Criar as regras de firewall filter no RouterOS que farão a coleta
```
/ip firewall filter
add action=passthrough chain=forward comment=MONITOR_TCP_SYN_COUNT connection-state=new protocol=tcp tcp-flags=syn
add action=passthrough chain=forward comment=MONITOR_UDP_NEW_COUNT connection-state=new protocol=udp
```

## 3 - Criar o Script Conforme abaixo:
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
Para testar se deu boa, pode rodar direto no terminal do mikrotik: ```/system/script/run get_counters_tcp_udp_json```
verá um resultado como: <br>
```{"MONITOR_TCP_SYN_COUNT": {"packets": 708555894, "bytes": 43545004564},"MONITOR_UDP_NEW_COUNT": {"packets": 32772666966, "bytes": 4195821380659}```


## 4 - Identificar o correto ID do Script com SNMP Walk:
snmpwalk -v2c -c comunity ip 1.3.6.1.4.1.14988.1.1.8.1.1.2

## 5 - Importar o template para o Zabbix
Feito para Zabbix 5, 6 e 7.

## 6 - Adicionar o Host criando a macro {$IDSCRIPT} com o ID correspondente ao Script. 
(pode criar o item macro no host mesmo) e usar a entrada "{$IDSCRIPT}" apontando para o value X (numero encontrado do script).

Em geral segue a lógica de:
1.3.6.1.4.1.14988.1.1.8.1.1.2.1 = primeiro script do mikrotik <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.2 = segundo script <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.3 = terceiro, e asim por diante. <br>
SE teve algum script excluido o routeros tmb conta o ID dele e não reutiliza mais. Então, por exemplo, se o terceiro e quarto scripts que existiam e foram excluidos, o ID será o 5.

<b>Veja o video abaixo do passo a passo completo.</b> <br><br>

<hr>

## English
# TCP/SYN and UDP/NEW Packet Counter Template
SSYN/TCP and UDP/NEW are basically packets that initiate new connections for their respective protocols.

By counting them, it is possible to get a general overview of the amount of TCP and UDP connections in PPS (Packets Per Second) and Bytes.

In scenarios where a CCR2216 is used with Offload correctly configured, connection opening packets are basically the only packets that "go up" to the CPU before the route is installed in the hardware. THAT IS WHY it is important to count them.

It is also possible to catch DDoS attacks like SYN Flood and any UDP amplification (ports 53 and 123, for example).

The Template is made for Zabbix 7 and creates a Dashboard for the device with the analyzed data. TIP: Compare the UDP/PPS graph with your MikroTik's CPU graph to see exactly when a DDoS occurred.

### STEP BY STEP:
## 1 - Enable an SNMP community with write permission 
(IMPORTANT: LIMIT to the Zabbix IP)
```
/snmp community
add addresses=100.100.100.50/32 name=zbx_wr1te write-access=yes
/snmp
set contact=xxx@exemplo.com.br enabled=yes location=Chapeco-SC
``` 
Replace  ```100.100.100.50/32``` with your Zabbix IP.

## 2 - Create the firewall filter rules in RouterOS that will perform the collection
```
/ip firewall filter
add action=passthrough chain=forward comment=MONITOR_TCP_SYN_COUNT connection-state=new protocol=tcp tcp-flags=syn
add action=passthrough chain=forward comment=MONITOR_UDP_NEW_COUNT connection-state=new protocol=udp
```

## 3 - Create the Script as shown below:
Use whatever name you want, I call it "get_counters_tcp_udp_json"
# RouterOS Script:
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
To test if it worked, you can run it directly in the MikroTik terminal: ```/system/script/run get_counters_tcp_udp_json```
you will see a result like: <br>
```{"MONITOR_TCP_SYN_COUNT": {"packets": 708555894, "bytes": 43545004564},"MONITOR_UDP_NEW_COUNT": {"packets": 32772666966, "bytes": 4195821380659}```


## 4 - Identify the correct Script ID with SNMP Walk:
snmpwalk -v2c -c comunity ip 1.3.6.1.4.1.14988.1.1.8.1.1.2

## 5 - Import the template into Zabbix
Made for Zabbix 5, 6 and 7.

## 6 - Add the Host creating the macro {$IDSCRIPT} with the ID corresponding to the Script. 
(you can create the macro item in the host itself) and use the entry "{$IDSCRIPT}" pointing to the value X (the script number found).

In general, it follows the logic of:
1.3.6.1.4.1.14988.1.1.8.1.1.2.1 = first script on mikrotik <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.2 = second script <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.3 = third, and so on <br>
IF a script was deleted, RouterOS also counts its ID and does not reuse it. So, for example, if the third and fourth scripts that existed were deleted, the ID will be 5.

<hr>

### PASSO A PASSO COMPLETO / STEP BY STEP:
https://github.com/user-attachments/assets/2ff2ff3a-7182-4e63-ac5f-89bdab45347e

### Host Dashboard:
<img width="1920" height="1523" alt="Image" src="https://github.com/user-attachments/assets/36590a45-a5d0-4c4f-8b18-f2f08e3f95a1" />

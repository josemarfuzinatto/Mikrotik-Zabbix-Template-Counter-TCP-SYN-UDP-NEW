# Tamplate Contador de pacotes TCP/SYN e UDP/NEW
Basicamente são pacotes de abertura de novas conexões.
Contando eles é possivel se ter um panorama geral de quantidade de conexões TCP e UDP em PPS e Bytes.

Em cenários onde se usa CCR2216 com Offload corretamente configurado, os pacotes de abertura são basicamente os únicos pacotes que "sobem" para a CPU antes da rota ser instalada no hardware. POR ISSO, é importante contabiliza-los.

Também é possivel pegar ataques DDoS do tipo SYN Flood e qualquer amplificação UDP (53 e 123 por exemplo)

O Tamplate é feito para Zabbix 7 e cria uma Dashboard para cada equipamento com os dados analisados. DICA: Compare o gráfico de UDP/PPS com o grafico de CPU de seu Mikrotik e veja exatamente quando se teve DDoS.

SEGUIR OS PASSOS:
1 - Habilitar uma comunidade SNMP com permissão de escrita (LIMITAR ao IP do Zabbix)
2 - Criar o Script Conforme abaixo:
{
# Script RouterOS
:local output "{"
:local first true

:local listaRegras {"MONITOR_TCP_SYN_COUNT"; "MONITOR_UDP_NEW_COUNT"}

:foreach nomeRegra in=$listaRegras do={
    :local foundIDs [/ip firewall filter find comment=$nomeRegra]
    
    :if ([:len $foundIDs] > 0) do={
        
        :local singleID [:pick $foundIDs 0]
        
        :local packets 0
        :local bytes 0
        
        :do {
            :set packets [/ip firewall filter get $singleID packets]
            :set bytes   [/ip firewall filter get $singleID bytes]
        } on-error={
            :put ("Erro ao ler dados da regra: " . $nomeRegra)
        }
        
        :if ($first = false) do={ :set output ($output . ",") }
        :set first false
        
        :set output ($output . "\"" . $nomeRegra . "\": {\"packets\": " . $packets . ", \"bytes\": " . $bytes . "}")
        
    } else={
        :put ("AVISO: Nao encontrei nenhuma regra com o comentario: " . $nomeRegra)
    }
}

:set output ($output . "}")

:put $output
}

3 - Identificar o correto ID do Script com SNMP Walk:
snmpwalk -v2c -c <comm> <ip> 1.3.6.1.4.1.14988.1.1.8.1.1.2
4 - Substituir na macro {$IDSCRIPT} pelo ID correspondente ao adicionar o tamplate no Host. (pode criar o item macro no host mesmo) e usar a entrada "{$IDSCRIPT}" apontando para o value X (numero encontrado do script).

Em geral segue a logica de:
1.3.6.1.4.1.14988.1.1.8.1.1.2.1 = primeiro script do mikrotik
1.3.6.1.4.1.14988.1.1.8.1.1.2.2 = segundo script
1.3.6.1.4.1.14988.1.1.8.1.1.2.3 = terceiro, e asim por diante.

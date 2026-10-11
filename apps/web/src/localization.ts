/** UI translation for legacy text while components migrate to typed message keys. */
const entries: Record<string,string> = {
'Visão geral':'Overview','Rede WAN/LAN':'WAN/LAN network','Ligações VPN':'VPN connections',
'Hosts e rotas':'Hosts and routes','Diagnóstico':'Diagnostics','Monitorização':'Monitoring',
'Registos':'Logs','Sistema':'System',
'ADMINISTRAÇÃO':'ADMINISTRATION','ACESSO ADMINISTRATIVO':'ADMINISTRATIVE ACCESS',
'Instalada:':'Installed:','Nova versão:':'New version:','Última versão não verificada':'Latest version not verified',
'Mais recente:':'Latest:','Estado do sistema, ligações e encaminhamentos':'System, connections and routing status',
'Hosts no Gateway':'Gateway hosts','Túneis activos confirmados':'Confirmed active tunnels',
'Hosts com política configurada':'Hosts with configured policies','Serviços do Gateway':'Gateway services',
'Rotas disponíveis':'Available routes','Estado das rotas e consumo':'Routes and usage',
'Hosts configurados no gateway':'Configured gateway hosts','Tráfego acumulado':'Total traffic',
'Tráfego encaminhado dos hosts geridos. Exclui tráfego próprio do gateway.':'Forwarded traffic from managed hosts. Excludes gateway traffic.',
'Configuração da rede':'Network configuration','Topologia WAN / LAN':'WAN/LAN topology',
'Interface de gestão do WebAdmin':'WebAdmin management interface','Modo de instalação':'Installation mode',
'Uma interface · LAN partilhada':'One interface · Shared LAN','WAN + LAN separadas (mín. 2 interfaces físicas)':'Separate WAN + LAN (min. 2 physical interfaces)',
'WAN + várias LANs (mín. 3 interfaces físicas)':'WAN + multiple LANs (min. 3 physical interfaces)',
'Interfaces WAN / LAN':'WAN / LAN interfaces','Não utilizada':'Unused','LAN / Clientes':'LAN / Clients',
'WAN / ISP':'WAN / ISP','Função':'Role','Tipo de endereço':'Address type','IP estático':'Static IP',
'DHCP (automático)':'DHCP (automatic)','Gateway IPv4':'IPv4 gateway','Prefixo CIDR':'CIDR prefix',
'Endereço IPv4':'IPv4 address','Servidores DNS IPv4 (separados por vírgulas)':'IPv4 DNS servers (comma-separated)',
'Configuração inválida:':'Invalid configuration:','A carregar interfaces…':'Loading interfaces…',
'Esta configuração é um rascunho e não altera endereços, rotas nem DNS do sistema.':'This is a draft and does not change system addresses, routes or DNS.',
'Guardar':'Save','Aplicar':'Apply','Cancelar':'Cancel','Editar':'Edit','Eliminar':'Delete',
'Estado do serviço DNS · verificado na API':'DNS service status · API verified',
'Serviço e administração':'Service and administration','Estatísticas reais · Pi-hole principal':'Live statistics · Primary Pi-hole',
'Dashboard Pi-hole':'Pi-hole dashboard','Abrir administração Pi-hole ↗':'Open Pi-hole administration ↗',
'Consultas DNS':'DNS queries','Consultas bloqueadas':'Blocked queries','Percentagem bloqueada':'Blocked percentage',
'Domínios nas listas':'Domains on lists','Filtragem do Pi-hole principal':'Primary Pi-hole filtering',
'Configurar':'Configure','Listas centralizadas':'Centralized lists',
'Criar ou configurar ligação VPN':'Create or configure VPN connection',
'Criar nova ligação…':'Create new connection…','Resumo das ligações VPN':'VPN connection summary',
'Nenhuma ligação VPN configurada.':'No VPN connections configured.',
'Nenhum perfil criado. Adicione um perfil para começar a desenhar as políticas.':'No profiles created. Add a profile to start configuring policies.',
'Nome':'Name','Nome da ligação':'Connection name','Fornecedor':'Provider','Protocolo':'Protocol',
'Perfil':'Profile','Perfis':'Profiles','Perfis de ligação':'Connection profiles','Perfis configurados':'Configured profiles',
'Guardar ligação':'Save connection','Seleccionar fornecedor…':'Select provider…',
'Outro / configuração própria':'Other / custom configuration','Perfil existente (opcional)':'Existing profile (optional)',
'Utilizador OpenVPN':'OpenVPN username','Palavra-passe OpenVPN':'OpenVPN password',
'Ou colar configuração':'Or paste configuration','Estado':'Status','Transporte':'Transport',
'IP público verificado':'Verified public IP','Handshake recente confirmado':'Recent handshake verified',
'Handshakes WireGuard recentes':'Recent WireGuard handshakes','Histórico individual · até 100 eventos':'Individual history · up to 100 events',
'Ainda sem eventos registados para esta ligação. O histórico começa após esta actualização.':'No events recorded for this connection yet. History starts after this update.',
'Sem eventos registados.':'No recorded events.','Adicionar regra de host':'Add host rule',
'Políticas por host':'Per-host policies','Políticas de hosts':'Host policies','Políticas efectivas no gateway':'Effective gateway policies',
'Políticas DIRECT configuradas':'Configured DIRECT policies','Identificador técnico (opcional)':'Technical ID (optional)',
'Identificador':'Identifier','Dispositivo identificado na rede':'Device discovered on network',
'Seleccione o dispositivo correcto…':'Select the correct device…','Introduzir IP manualmente…':'Enter IP manually…',
'Identidade MAC':'MAC identity','MAC associado':'Registered MAC','Rota pretendida':'Desired route',
'Rota efectiva':'Effective route','Saída':'Egress',
'Saída directa':'Direct egress','Saídas configuradas':'Configured egress routes',
'BLOQUEADO (sem Internet)':'BLOCKED (no Internet)','DIRECT (sem VPN)':'DIRECT (no VPN)',
'DESABILITADO':'DISABLED','Não definido':'Not set','Não verificado':'Not verified',
'Adicionar política':'Add policy','+ Guardar política':'+ Save policy',
'Remover host':'Remove host','Confirmar VPN':'Confirm VPN',
'Políticas e identidades':'Policies and identities','Hosts configurados':'Configured hosts',
'Estado da política':'Policy status','Verificação efectiva no gateway':'Effective gateway verification',
'Verificação real':'Live verification','Ambiente actual · leitura em tempo real':'Current environment · live data',
'Capacidades do servidor':'Server capabilities','Consulta sem alterações':'Read-only query',
'Identidade não verificável nesta descoberta':'Identity cannot be verified from this discovery',
'Kernel · 10 s':'Kernel · 10 s','Firewall':'Firewall','Kill switch':'Kill switch',
'Autorizado':'Authorized','MAC diferente':'MAC mismatch','Não verificável':'Cannot verify',
'Sem resultados da verificação.':'No verification results.','A carregar capacidades…':'Loading capabilities…',
'Filtrar eventos':'Filter events','Data / hora':'Date / time','Descrição':'Description','Detalhes':'Details',
'Evento':'Event','Data':'Date','Medição real · actualização 5 s':'Live measurements · refresh every 5 s',
'Estado real · actualização 5 s':'Live status · refresh every 5 s',
'Sem medições disponíveis.':'No measurements available.',
'Túneis ligados':'Connected tunnels','Túneis WireGuard ligados':'Connected WireGuard tunnels',
'VPNs (WireGuard / OpenVPN)':'VPNs (WireGuard / OpenVPN)',
'Vel. download':'Download speed','Vel. upload':'Upload speed',

'Gateway doméstico e empresarial seguro e flexível':'Secure and flexible home and business gateway',
'Portugal':'Portugal','Privacidade':'Privacy','Controlo':'Control','Liberdade':'Freedom',
'A verificar':'Checking','Operacional':'Operational',
'Ligado':'Connected','Desligado / não verificado':'Disconnected / not verified',
'Verificada':'Verified','Falha':'Failure','Protecção presente':'Protection active',
'Sem observação':'Not observed','Não aplicável':'Not applicable',
'◉  Estado das rotas e consumo':'◉  Routes and usage',
'Erro: host diferente':'Error: different host','Erro — Host não autorizado':'Error — Unauthorized host',
'Em execução':'Running','Medido':'Measured'
};
const additions: Record<string,string> = {
'Actualização:':'Updated:','túnel(is) ligado(s)':'tunnels connected','de 5':'of 5',
'Consumo acumulado por host e rota, persistente após reinício; exclui tráfego do gateway.':'Accumulated usage by host and route, preserved across restarts; gateway traffic excluded.',
'Velocidade de tráfego encaminhado · últimos 5 segundos':'Forwarded traffic speed · last 5 seconds',
'Internet directa':'Direct Internet','Disponível':'Available','Indisponível':'Unavailable','Sem hosts':'No hosts',
'Gestão:':'Management:','LAN / CLIENTES':'LAN / CLIENTS','IP ESTÁTICO':'STATIC IP','rota padrão':'default route',
'Diagrama conforme a modalidade e as interfaces seleccionadas na configuração inicial. Os valores propostos podem diferir da rede em execução. Guardar não altera interfaces, gateway, DNS ou firewall.':'Diagram based on the selected topology and interfaces. Proposed values may differ from the running network. Saving does not modify interfaces, gateway, DNS or firewall.',
'Seleccione as interfaces físicas e as respectivas funções. Nesta versão, guardar cria apenas um rascunho; confirmar valida a topologia existente, sem modificar a rede.':'Select physical interfaces and their roles. Saving creates a draft; confirmation checks the existing topology without changing the network.',
'Configuração confirmada':'Configuration confirmed',
'Dados recolhidos do Pi-hole principal. O resolvedor VPN tem cache e estatísticas próprias; os seus pedidos não estão incluídos nestes totais. Consultas em cache no principal:':'Data collected from the primary Pi-hole. The VPN resolver has separate cache and statistics; its queries are not included in these totals. Primary cache hits:',
'IP público:':'Public IP:','Protecção por host:':'Per-host protection:',
'Sem hosts associados.':'No associated hosts.',
'Recebido:':'Received:','Enviado:':'Sent:','Não medido':'Not measured',
'MAC detectado:':'Detected MAC:','Não observado':'Not observed',
'Vizinhos observados na LAN; o estado é da cache, não um teste de conectividade. Nomes só aparecem quando confirmados.':'LAN neighbors are shown from the neighbor cache, not an active connectivity test. Names are only displayed when verified.',
'GATEWAY / DIAGNÓSTICO':'GATEWAY / DIAGNOSTICS',
'Diagnóstico dos túneis e das políticas de host actualmente geridos no ASUS. Para testar perdas de ligação, DNS e IPv6 nos clientes, consulte os testes de aceitação executados directamente nos equipamentos.':'Diagnostics of currently managed tunnels and host policies. Test VPN outages, DNS and IPv6 directly on client devices.',
'Associações configuradas':'Configured assignments','Estado dos túneis':'Tunnel status',
'DNS: regras configuradas, fuga não comprovada; IPv6: não suportado / bloqueado':'DNS rules configured, no-leak not verified; IPv6 unsupported / blocked',
'Uma política activa não certifica, por si só, ausência de fugas. A verificação de rota efectiva, MAC observado e tráfego deve ser efectuada com os testes reais dos clientes.':'An active policy alone does not certify the absence of leaks. Verify the effective route, observed MAC and traffic on real clients.',
'Saída pública OpenVPN verificada':'OpenVPN public egress verified',
'Sem observação':'Not observed','Política activa':'Active policy',
'A carregar':'Loading','Últimos':'Latest','Sem Internet':'No Internet',
'Bloqueado':'Blocked','Ligada':'Connected','Desligada':'Disconnected',
'Verificação pendente':'Pending verification','Aguardar confirmação':'Awaiting confirmation',
'Falha ao':'Failed to','Não foi possível':'Could not',
};
Object.assign(entries,additions,{
'Os ficheiros de configuração podem conter chaves privadas e certificados. Não serão apresentados após importação.':'Configuration files may contain private keys and certificates. They will not be displayed after import.',
'Depois de guardar o perfil e o ficheiro WireGuard, utiliza Ligar/Desligar na tabela acima. A associação efectiva de hosts à VPN continuará bloqueada até o encaminhamento fail-closed estar validado.':'After saving the profile and WireGuard configuration, use Connect/Disconnect above. Host assignment requires validated fail-closed routing.',

'últimos 5 segundos':'last 5 seconds',
'últimos':'last',
'Ficheiro de configuração WireGuard (.conf)':'WireGuard configuration file (.conf)',
'WireGuard utiliza chaves e um ficheiro de configuração, não utilizador e palavra-passe. A importação segura ficará associada ao perfil.':'WireGuard uses keys and a configuration file rather than a username and password. Secure import is linked to the profile.',
'Configuração OpenVPN validada e guardada':'OpenVPN configuration validated and saved',
'Configuração WireGuard validada e guardada':'WireGuard configuration validated and saved',
'Configuração validada e guardada':'Configuration validated and saved',
'Perfil importado':'Profile imported',
'Ficheiro de configuração':'Configuration file',
'A importação segura ficará associada ao perfil.':'The secure import will be linked to the profile.',

'Velocidade de tráfego encaminhado':'Forwarded traffic speed',
'Dados recolhidos do Pi-hole principal.':'Data collected from the primary Pi-hole.',
'O resolvedor VPN tem cache e estatísticas próprias; os seus pedidos não estão incluídos nestes totais.':'The VPN resolver has its own cache and statistics; its queries are excluded from these totals.',
'Consultas em cache no principal:':'Primary cache hits:',
'Gerida nas políticas e firewall dos hosts.':'Managed by host policies and firewall.',
'Gerida nas políticas':'Managed by policies',
'firewall dos hosts':'host firewall',
'A aguardar importação':'Awaiting import',
'A aguardar handshake':'Awaiting handshake',
'Ligar':'Connect','Desligar':'Disconnect',
'Diagnóstico dos túneis e das políticas de host actualmente geridos no gateway.':'Diagnostics of tunnels and host policies currently managed by the gateway.',
'Para testar perdas de ligação, DNS e IPv6 nos clientes, consulte os testes de aceitação executados directamente nos equipamentos.':'To test connection failures, DNS and IPv6, run validation on the client devices.',
'actualmente geridos no gateway':'currently managed by the gateway',
'políticas de host':'host policies',
'Túnel OpenVPN iniciado':'OpenVPN tunnel started',
'Pedido de ligação recebido':'Connection request received',
'Ligação iniciada':'Connection started',
'Ligação terminada':'Connection stopped',
'Ligação estabelecida':'Connection established',
'Ligação recusada':'Connection refused',
'Falha na ligação':'Connection failed',
'Perfil ligado':'Profile connected',
'Perfil desligado':'Profile disconnected',
'Endereço IP público verificado':'Public IP address verified',
'Handshake verificado':'Handshake verified',
'Verificação de saída':'Egress verification',
'Sem handshake recente':'No recent handshake',
'Alteração de rota':'Route change',
'Política aplicada':'Policy applied',
'Política revertida':'Policy rolled back',
});
Object.assign(entries,{
'Nenhuma política definida. Hosts sem política não serão automaticamente incluídos numa VPN.':'No policies defined. Hosts without policies will not be automatically included in a VPN.',
'a aguardar':'waiting',
'Em descoberta':'Discovering',
'Em espera':'Waiting',
'Nenhuma política definida.':'No policies defined.',
'Hosts sem política não serão automaticamente incluídos numa VPN.':'Hosts without policies will not be automatically included in a VPN.',
'Interface partilhada · rascunho':'Shared interface · draft',
'LIGAÇÃO À INTERNET · REDE PARTILHADA':'INTERNET CONNECTION · SHARED NETWORK',
'WAN/LAN na mesma interface':'WAN/LAN on one interface',
'4 clientes activos':'4 active clients',
'clientes activos':'active clients',
'Perfis VPN':'VPN profiles',
'Últimos 100 eventos VPN':'Latest 100 VPN events',
'Interface iniciada, a aguardar handshake':'Interface started, awaiting handshake',
'Interface WireGuard desligada':'WireGuard interface disconnected',
'Ligado · handshake recente':'Connected · recent handshake',
'Interface activa · a aguardar handshake':'Interface active · awaiting handshake',
'Configurado · desligado':'Configured · disconnected',
'Ficheiro inválido':'Invalid file',
'A aguardar importação .conf':'Awaiting .conf import',
'A estabelecer ligação':'Connecting',
'A aguardar importação .ovpn e credenciais':'Awaiting .ovpn import and credentials',
'Ligado':'Connected','Desligado':'Disconnected','Rascunho':'Draft','rascunho':'draft','partilhada':'shared',
'Activo':'Active','Activa':'Active','Activos':'Active','Activas':'Active',
'Ligada':'Connected','Desligada':'Disconnected',
'Selecionar':'Select','Seleccionar':'Select','Guardar':'Save','Remover':'Remove',
'Erro de política':'Policy error','Revertido':'Reverted',
'Estado efectivo por host':'Effective per-host status',
'Rota por host':'Per-host route',
'Per-host policies':'Per-host policies',
'Sem interface':'No interface',
'Ficheiro ZIP de configuração CyberGhost':'CyberGhost configuration ZIP file',
'Ficheiro de configuração OpenVPN (.ovpn ou .conf)':'OpenVPN configuration file (.ovpn or .conf)',
'Utilizador OpenVPN / IKEv2 (não o email da conta)':'OpenVPN / IKEv2 username (not account email)',
'Utilizador das credenciais manuais do CyberGhost':'CyberGhost manual-configuration username',
'Utilizador fornecido pelo serviço VPN':'Username provided by the VPN service',
'Palavra-passe da configuração OpenVPN':'OpenVPN configuration password',
'Seleccionado:':'Selected:',
'Não registado':'Not registered',
'Sem resultados':'No results',
'Vizinhos observados na LAN':'Neighbors observed on the LAN',
'Em descoberta…':'Discovering…',
'Descoberta indisponível':'Discovery unavailable',
'Seleccione um dispositivo':'Select a device',
'política existente':'existing policy',
'A recolher amostras de velocidade…':'Collecting speed samples…',
'Sem contadores reais disponíveis':'No real counters available',
'Interface:':'Interface:',
'Histórico de velocidades de download e upload':'Download and upload speed history',
'Dispositivo TUN:':'TUN device:',
'Registos VPN':'VPN logs',
});
const shortTerms: Record<string,string> = {
'Ligado':'Connected','Desligado':'Disconnected','Rascunho':'Draft','rascunho':'draft','partilhada':'shared',
'Activo':'Active','Activa':'Active','Activos':'Active','Activas':'Active',
'Ligada':'Connected','Desligada':'Disconnected',
'Guardar':'Save','Remover':'Remove','Editar':'Edit','Eliminar':'Delete',
'Últimos':'Latest','últimos':'last','segundos':'seconds',
};
const sorted=Object.entries(entries).sort((a,b)=>b[0].length-a[0].length);
function translate(s:string):string {
  if(!s.trim())return s;
  const match=s.match(/^(\s*)(.*?)(\s*)$/s);
  if(!match)return s;
  const exact=entries[match[2]];
  if(exact)return match[1]+exact+match[3];
  let body=match[2];
  for(const [pt,en] of sorted) {
    if(pt.length<9)continue;
    body=body.split(pt).join(en);
  }
  for(const [pt,en] of Object.entries(shortTerms)){
    body=body.replace(new RegExp('(^|[^\\p{L}\\p{N}])'+pt+'(?=$|[^\\p{L}\\p{N}])','gu'),(_match,prefix:string)=>prefix+en);
  }
  body=body.split('últimos 5 segundos').join('last 5 seconds');
  return match[1]+body+match[3];
}
const baseline=new WeakMap<Node,{original:string,last:string}>();
const attributeBaseline=new WeakMap<Element,Record<string,{original:string,last:string}>>();
export function installGlobalTranslation(language:'pt'|'en'):()=>void {
  document.documentElement.lang=language==='en'?'en':'pt-PT';
  let running=false;
  function update(){
    if(running)return;
    running=true;
    try {
      const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
      let node:Node|null;
      while((node=walker.nextNode())){
        if(!node.parentElement || ['SCRIPT','STYLE','TEXTAREA'].includes(node.parentElement.tagName))continue;
        const current=node.textContent||'';
        let item=baseline.get(node);
        if(!item || (current!==item.last && current!==item.original)){item={original:current,last:current};}
        const next=language==='en'?translate(item.original):item.original;
        if(current!==next)node.textContent=next;
        baseline.set(node,{original:item.original,last:next});
      }
      for(const element of Array.from(document.querySelectorAll('[placeholder],[title],[aria-label]'))){
        const remembered=attributeBaseline.get(element)||{};
        for(const name of ['placeholder','title','aria-label']){
          const current=element.getAttribute(name);
          if(current===null)continue;
          let item=remembered[name];
          if(!item || (current!==item.last && current!==item.original))item={original:current,last:current};
          const next=language==='en'?translate(item.original):item.original;
          if(current!==next)element.setAttribute(name,next);
          remembered[name]={original:item.original,last:next};
        }
        attributeBaseline.set(element,remembered);
      }
    }finally{running=false;}
  }
  // Translate newly rendered views and asynchronously refreshed data.
  const observer=new MutationObserver(()=>update());
  update();
  observer.observe(document.body,{childList:true,characterData:true,subtree:true});
  return ()=>{observer.disconnect();};
}

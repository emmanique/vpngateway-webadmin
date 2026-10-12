import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import {installGlobalTranslation} from './localization';
type WgProfileStatus = {id:string;name:string;stored:boolean;format_valid:boolean;peer_count:number;address_present:boolean;dns_present:boolean;endpoint_present:boolean;tunnel_active:boolean;connected?:boolean;tunnel_state?:string;interface_name?:string|null;received_bytes?:number|null;sent_bytes?:number|null;last_handshake_at?:number|null;transport?:string|null;public_ipv4?:string|null;kill_switch_active?:boolean};
type Connection = { id:string; name:string; provider:string; protocol:'wireguard'|'openvpn'; enabled:boolean; status:string; configuration_stored?:boolean };
type Policy = { id:string; host_ip:string; destination:string; failure_mode:string; status:string; registered_mac?:string|null; vpn_pending?:boolean; vpn_deadline?:number };
type DirectStatus = {host_ip:string;gateway_ip:string;destination:string;service:string;active:boolean;vpn_used:boolean;scope:string;management:string;service_active?:boolean;firewall_rules_verified?:boolean;counters?:{forward_packets:number;return_packets:number;nat_packets:number};snapshot_timestamp?:string};
type DirectHosts = {hosts:{host_ip:string;service:string;service_active:boolean;route_verified:boolean;firewall_verified:boolean|null;forward_packets:number|null;return_packets:number|null;nat_packets:number|null;traffic_observed:boolean;active:boolean;verification:string}[];vpn_routing_active:boolean;observed_at?:string};
type DirectProbe = {mode:string;vpn_used:boolean;client_forwarding_tested:boolean;route:string|null;reachable:boolean;http_status:number|null;public_ipv4?:string;warp?:string;error?:string;timestamp:string};
type Runtime = {mode:string;network_changes_enabled:boolean;tools:Record<string,boolean>;capabilities:Record<string,boolean>;tun_device:boolean;isolation:string;tunnels:unknown[]};
type Live = {version:string;scope:string;clients:Record<string,{route:string}>;wireguard:{interface_present:boolean;handshake_observed:boolean};kill_switch:{loaded:boolean};vpn_client_ready:boolean;read_only:boolean};
type OverviewStatus = {installed_version:string;latest_version:string|null;update_available:boolean|null;routes:{id:string;name:string;available:boolean;active:boolean;hosts:{ip:string;status:string;authorization_status?:string;rx_bps:number|null;tx_bps:number|null;rx_bytes:number|null;tx_bytes:number|null}[];rx_bps:number|null;tx_bps:number|null;note:string}[];sample_interval_seconds:number;traffic_metrics_available:boolean;services?:{pihole_dns:boolean;wireguard_connected:number;vpn_connected:number;vpn_tunnels:{id:string;name:string;protocol:string;connected:boolean;interface:string|null}[]}};
type MenuIconName = 'home'|'network'|'shield'|'lock'|'route'|'monitor'|'logs'|'settings'|'diagnostic';
function MenuIcon({name}:{name:MenuIconName}) {
  const paths:Record<MenuIconName,React.ReactNode> = {
    home:<><path d="m3 10 9-7 9 7"/><path d="M5 9v12h14V9"/><path d="M9 21v-7h6v7"/></>,
    network:<><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-4h14v4"/></>,
    shield:<path d="M12 2 20 5v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3Zm0 0v20"/>,
    lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1"/></>,
    route:<><path d="M3 7h18l-4-4m4 4-4 4M21 17H3l4-4m-4 4 4 4"/></>,
    monitor:<><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></>,
    logs:<><path d="M7 2h8l5 5v14H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Zm8 0v5h5M9 12h7M9 16h7"/></>,
    settings:<><circle cx="12" cy="12" r="3"/><path d="M10 2h4l.6 2.3 2 .9 2.1-1.1 2.8 2.8-1.1 2.1.9 2L23 11v3l-2.3.6-.9 2 1.1 2.1-2.8 2.8-2.1-1.1-2 .9L14 23h-4l-.6-2.3-2-.9-2.1 1.1-2.8-2.8 1.1-2.1-.9-2L1 14v-3l2.3-.6.9-2-1.1-2.1 2.8-2.8 2.1 1.1 2-.9L10 2Z"/></>,
    diagnostic:<><path d="M3 12a9 9 0 1 0 9-9v9l6 3"/><path d="M12 3v9"/></>
  };
  return <svg className="menu-icon" viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
type CutoverStatus = {policy:string;profile:string;checks:Record<string,boolean>;blockers:string[];kernel_route_observation:{kernel_direct_route:boolean;kernel_vpn_route:boolean;route_lookup_ok:boolean};vpn_public_ipv4:string|null;cutover_enabled:boolean;network_changes:boolean};
type Page = 'overview'|'network'|'dns'|'connections'|'policies'|'diagnostics'|'monitoring'|'logs'|'system';
type DnsDraft = {enabled:boolean;upstream_ipv4:string[];block_on_vpn_failure:boolean;lan_only:boolean};
type DnsBindings = {management_ipv4:string|null;management_interface:string|null;webadmin_port:number;pihole_admin_port:number;dns_port:number;pihole_admin_url:string|null;applied:boolean;ready:boolean};
type DnsAdminStatus = {installed:boolean;running:boolean;admin_available:boolean;admin_url:string|null;note:string};
type DnsPlan = {applied:boolean;safe_to_apply:boolean;groups:{id:string;clients:string[];upstream_route:string;deny_non_vpn_dns:boolean;ready:boolean;reasons:string[]}[]};
type NetworkTopology = {interfaces:{interface:string;address:string;network:string;operstate:string;kind:string;default_route:boolean}[];default_routes:{interface:string;gateway:string}[]};
type NetworkDraft = {mode:'shared'|'routed'|'multi_lan';management_interface:string;wan_webadmin_enabled?:boolean;wan_webadmin_allowed_cidrs?:string[];interfaces:{interface:string;role:'wan'|'lan'|'unused';label:string;address_mode?:'static'|'dhcp'|null;ipv4_address?:string|null;prefix_length?:number|null;gateway_ipv4?:string|null;dns_ipv4?:string[]}[]};
const API = '/api';
async function request<T>(url:string, init?:RequestInit):Promise<T> {
  const response = await fetch(API + url, { ...init, headers: { 'Content-Type':'application/json', ...(init?.headers || {}) } });
  if (!response.ok) { const data = await response.json().catch(() => ({})); const detail=data.detail; const message=typeof detail==='string'?detail:Array.isArray(detail)?detail.map((e:{msg?:string;loc?:string[]})=>((e.loc||[]).filter(x=>x!=='body').join('.')+': '+(e.msg||'Valor inválido'))).join(' · '):'Pedido recusado (HTTP '+response.status+')'; throw new Error(message); }
  return response.status === 204 ? undefined as T : response.json();
}
function App() {
  const [page,setPage] = useState<Page>('overview');
  const [language,setLanguage] = useState<'pt'|'en'>(()=>localStorage.getItem('vpngw-language')==='en'?'en':'pt');
  const [restoreFile,setRestoreFile] = useState<File|null>(null);
  const [backupPassword,setBackupPassword] = useState('');
  const [restorePassword,setRestorePassword] = useState('');
  const [restorePreflight,setRestorePreflight] = useState<{compatible:boolean;issues:string[];vpn_count:number;host_count:number;mapping:Record<string,string>;options:Record<string,string[]>;pending:string[]}|null>(null);
  const [interfaceMapping,setInterfaceMapping] = useState<Record<string,string>>({});
  const [maintenanceBusy,setMaintenanceBusy] = useState(false);
  const [restoreConfirm,setRestoreConfirm] = useState('');
  const [resetConfirm,setResetConfirm] = useState('');
  const [restoreError,setRestoreError] = useState('');
  const translations = {
    pt:{system:'Sistema',status:'Estado da aplicação',checking:'A verificar',profiles:'Perfis VPN',hosts:'Hosts',dns:'DNS Pi-hole',connected:'VPNs ligadas',storage:'Armazenamento utilizado',operational:'Operacional',unverified:'Não verificado',backup:'Backup de configuração',download:'Descarregar backup',restore:'Restaurar configuração',choose:'Seleccionar backup JSON',restoreButton:'Restaurar',defaults:'Predefinições',resetButton:'Repor predefinições',notice:'Backup integral cifrado com palavra-passe (mínimo 12 caracteres). O restauro substitui TODAS as VPNs, hosts e regras existentes. Desligue túneis e políticas antes de restaurar.',confirmRestore:'Escreva RESTORE para confirmar',confirmReset:'Escreva RESET para confirmar',completed:'Operação concluída',language:'Idioma',database:'Base de dados',password:'Palavra-passe do backup',restorePassword:'Palavra-passe do ficheiro',warning:'Verifique a topologia e as regras antes de voltar a aplicar as políticas.'},
    en:{system:'System',status:'Application status',checking:'Checking',profiles:'VPN profiles',hosts:'Hosts',dns:'Pi-hole DNS',connected:'Connected VPNs',storage:'Storage used',operational:'Operational',unverified:'Not verified',backup:'Configuration backup',download:'Download backup',restore:'Restore configuration',choose:'Select backup JSON',restoreButton:'Restore',defaults:'Factory defaults',resetButton:'Reset to defaults',notice:'Full encrypted backup (minimum 12-character password). Restore REPLACES ALL existing VPNs, hosts and rules. Disconnect tunnels and host policies first.',confirmRestore:'Type RESTORE to confirm',confirmReset:'Type RESET to confirm',completed:'Operation complete',language:'Language',database:'Database',password:'Backup password',restorePassword:'Backup file password',warning:'Verify the network topology and host rules before reapplying policies.'}
  };
  const t=translations[language];
  useEffect(()=>{localStorage.setItem('vpngw-language',language);},[language]);
  useEffect(()=>installGlobalTranslation(language),[language]);
  async function downloadBackup() {
    setMaintenanceBusy(true);
    try {
      const response=await fetch('/api/v1/system/backup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:backupPassword})});
      if(!response.ok){const error=await response.json().catch(()=>({}));throw new Error(error.detail||String(response.status));}
      const blob=await response.blob();
      const link=document.createElement('a');const url=URL.createObjectURL(blob);
      link.href=url;link.download='gateway-vpn-encrypted.json';document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);
      setMessage(t.completed);
    }catch(e){setMessage(String(e));}finally{setMaintenanceBusy(false);}
  }
  async function checkRestore() {
    setMaintenanceBusy(true);setRestorePreflight(null);setRestoreError('');
    try {
      const backup=JSON.parse(await restoreFile!.text());
      const result=await request<{compatible:boolean;issues:string[];vpn_count:number;host_count:number;mapping:Record<string,string>;options:Record<string,string[]>;pending:string[]}>('/v1/system/restore/preflight',{method:'POST',body:JSON.stringify({backup,password:restorePassword,interface_mapping:interfaceMapping})});
      setRestorePreflight(result);setInterfaceMapping(result.mapping);
      setMessage(result.compatible?(language==='pt'?'Servidor compatível. Confirme a substituição integral.':'Server compatible. Confirm full replacement.'):(language==='pt'?'Restauro bloqueado: incompatibilidades detectadas.':'Restore blocked: compatibility conflicts detected.'));
    } catch(e){setRestorePreflight(null);setMessage(String(e));} finally {setMaintenanceBusy(false);}
  }
  async function applyMaintenance(kind:'restore'|'defaults') {
    setMaintenanceBusy(true);
    try {
      const backup=kind==='restore'?JSON.parse(await restoreFile!.text()):null;
      await request('/v1/system/'+kind,{method:'POST',body:JSON.stringify({confirmation:kind==='restore'?'RESTORE':'RESET',backup,password:kind==='restore'?restorePassword:undefined,interface_mapping:kind==='restore'?interfaceMapping:undefined})});
      if(kind==='restore')setRestoreConfirm('');else setResetConfirm('');setRestoreFile(null);setRestorePassword('');setRestorePreflight(null);setInterfaceMapping({});setMessage(t.completed+' — '+t.warning);
      await refresh();
    }catch(e){setRestoreError(String(e));setMessage(String(e));}finally{setMaintenanceBusy(false);}
  }

  const [overviewStatus,setOverviewStatus] = useState<OverviewStatus|null>(null);
  const [trafficHistory,setTrafficHistory] = useState<{time:number;download:number;upload:number}[]>([]);
  const [statusUpdated,setStatusUpdated] = useState<string>('');
  const [live,setLive] = useState<Live|null>(null);
  const [topology,setTopology] = useState<NetworkTopology|null>(null);
  const [networkDraft,setNetworkDraft] = useState<NetworkDraft|null>(null);
  const [networkSaved,setNetworkSaved] = useState(false);
  const [networkApplied,setNetworkApplied] = useState(false);
  const [dnsDraft,setDnsDraft] = useState<DnsDraft>({enabled:false,upstream_ipv4:[],block_on_vpn_failure:true,lan_only:true});
  const [dnsServers,setDnsServers] = useState('');
  const [dnsPlan,setDnsPlan] = useState<DnsPlan|null>(null);
  const [dnsLive,setDnsLive] = useState<{stats:{total:number;blocked:number;percent_blocked:number;domains:number;active_clients:number;cached:number}|null;primary_dns:boolean;vpn_resolver_reachable:boolean|null;vpn_host_mode:string|null;vpn_host_guard:boolean;vpn_host_routed:boolean;admin_url:string|null}|null>(null);
  const [dnsSummary,setDnsSummary] = useState<{reachable:boolean;version:string|null;dns_enabled:boolean|null;admin_url?:string|null}|null>(null);
  const [dnsAdmin,setDnsAdmin] = useState<DnsAdminStatus|null>(null);
  const [dnsBindings,setDnsBindings] = useState<DnsBindings|null>(null);
  const [connections,setConnections] = useState<Connection[]>([]);
  const [wgStatuses,setWgStatuses] = useState<WgProfileStatus[]>([]);
  const [selectedVpnLog,setSelectedVpnLog] = useState<string>("");
  const [vpnEvents,setVpnEvents] = useState<{at:string;event:string;detail:string}[]>([]);
  const [policies,setPolicies] = useState<Policy[]>([]);
  const [identityBusy,setIdentityBusy]=useState(false);
  const [editingIdentity,setEditingIdentity]=useState<string|null>(null);
  const [draftIdentityMac,setDraftIdentityMac]=useState('');
  async function saveHostIdentity(id:string,mac:string) {
    setIdentityBusy(true);
    try {
      await request('/v1/policies/'+encodeURIComponent(id)+'/identity',{method:'PUT',body:JSON.stringify({registered_mac:mac})});
      const updated=await request<Policy[]>('/v1/policies');setPolicies(updated);
      setMessage('Identidade do host registada sem alterações na rede.');
    } catch(error){setMessage('Não foi possível registar a identidade: '+String(error));}
    finally{setIdentityBusy(false);}
  }
  const [genericPreviewHost,setGenericPreviewHost]=useState('');
  const [genericPreviewVpn,setGenericPreviewVpn]=useState('');
  const [genericPreview,setGenericPreview]=useState<{policy:string;host_ipv4:string;route_name:string;vpn_id:string;vpn_name:string;vpn_protocol:string;checks:Record<string,boolean>;cutover_enabled:boolean}|null>(null);
  const [genericPreviewError,setGenericPreviewError]=useState('');
  async function checkGenericPreview() {
    setGenericPreview(null);setGenericPreviewError('');
    if(!genericPreviewHost||!genericPreviewVpn){setGenericPreviewError('Seleccione primeiro um host e uma VPN.');return;}
    try {
      const result=await request<{policy:string;host_ipv4:string;route_name:string;vpn_id:string;vpn_name:string;vpn_protocol:string;checks:Record<string,boolean>;cutover_enabled:boolean}>('/v1/policies/'+encodeURIComponent(genericPreviewHost)+'/vpn-generic-preview?profile_id='+encodeURIComponent(genericPreviewVpn));
      setGenericPreview(result);
    } catch(e) {setGenericPreviewError(String(e));}
  }
  const [cutoverReports,setCutoverReports] = useState<Record<string,CutoverStatus>>({});
  const [cutoverErrors,setCutoverErrors] = useState<Record<string,string>>({});
  const [cutoverLoading,setCutoverLoading] = useState(false);
  const [policyRuntime,setPolicyRuntime] = useState<Record<string,{status:string;applied:boolean;deadline?:number;reason?:string}>>({});
  const [monitorRows,setMonitorRows] = useState<{ip:string;route:string;rx_bytes:number|null;tx_bytes:number|null;rx_bps:number|null;tx_bps:number|null;status:string}[]>([]);
  const [monitorSamples,setMonitorSamples] = useState<{download:number;upload:number}[]>([]);
  const [logFilter,setLogFilter] = useState('');
  const [eventRows,setEventRows] = useState<{at:string;profile:string;event:string;detail:string}[]>([]);
  const [healthSummary,setHealthSummary] = useState<{webadmin:string;profiles:number;policies:number;database:string;disk_total_bytes:number;disk_used_bytes:number;services?:{pihole_dns:boolean;vpn_connected:number}}|null>(null);
  const [diagnosticRows,setDiagnosticRows] = useState<{ip:string;destination:string;route_verified:boolean;firewall_verified:boolean;mac_guard_verified:boolean;identity:string;observed_mac?:string|null;registered_mac?:string|null;vpn_guard_present?:boolean|null;observed_route?:string}[]>([]);
  const [diagnosticError,setDiagnosticError] = useState('');
  const [moduleError,setModuleError] = useState('');
  const [message,setMessage] = useState('');
  const [editingHost,setEditingHost] = useState<string|null>(null);
  const [draftHostRoute,setDraftHostRoute] = useState('direct');
  const [runtime,setRuntime] = useState<Runtime|null>(null);
  const [direct,setDirect] = useState<DirectProbe|null>(null);
  const [directStatus,setDirectStatus] = useState<DirectStatus|null>(null);
  const [directHosts,setDirectHosts] = useState<DirectHosts|null>(null);
  const [directError,setDirectError] = useState('');
  const [testingDirect,setTestingDirect] = useState(false);
  const [busy,setBusy] = useState(false);
  const [connection,setConnection] = useState({id:'',name:'',provider:'',protocol:'wireguard' as 'wireguard'|'openvpn'});
  const [openVpnUsername,setOpenVpnUsername] = useState('');
  const [openVpnPassword,setOpenVpnPassword] = useState('');
  const [vpnConfigFile,setVpnConfigFile] = useState<File|null>(null);
  const [vpnConfigText,setVpnConfigText] = useState('');
  const [policy,setPolicy] = useState({id:'',host_ip:'',destination:'direct'});
  useEffect(()=>{if(!selectedVpnLog)return;let mounted=true;const update=async()=>{try{const data=await request<{events:{at:string;event:string;detail:string}[]}>('/v1/wireguard/'+encodeURIComponent(selectedVpnLog)+'/events');if(mounted)setVpnEvents(data.events);}catch{if(mounted)setVpnEvents([]);}};void update();const timer=setInterval(()=>void update(),5000);return()=>{mounted=false;clearInterval(timer);};},[selectedVpnLog]);
  async function checkVpnRouting(profileId:string) {
    const client=policies[0];
    if(!client){setMessage('Adiciona primeiro uma política de host para validar a rota VPN.');return;}
    setBusy(true);setMessage('');
    try {
      const result=await request<{ready:boolean;blockers:string[];facts:{vpn_connected:boolean;shared_lan:boolean}}>('/v1/wireguard/'+encodeURIComponent(profileId)+'/routing-readiness?host_ip='+encodeURIComponent(client.host_ip));
      setMessage('Encaminhamento VPN para '+client.host_ip+': '+(result.ready?'Pré-validação aprovada.':'NÃO PRONTO. ')+' '+result.blockers.join(' | ')+'. Nenhuma regra foi alterada.');
    }catch(e){setMessage('Pré-validação VPN indisponível: '+String(e));}
    finally{setBusy(false);}
  }
  async function runCutoverDiagnostics() {
    setCutoverLoading(true);
    const mapping:[string,string][]=[]; // Laboratório legado isolado da descoberta dinâmica
    const reports:Record<string,CutoverStatus>={};
    const errors:Record<string,string>={};
    await Promise.all(mapping.map(async([host,profile])=>{
      try {
        const result=await request<CutoverStatus>('/v1/policies/'+host+'/vpn-cutover-status?profile_id='+encodeURIComponent(profile));
        reports[host]=result;
      } catch(error) {errors[host]=String(error);}
    }));
    setCutoverReports(reports);
    setCutoverErrors(errors);
    setCutoverLoading(false);
  }
  async function probeVpnIp(profileId:string) {
    setBusy(true);setMessage('');
    try {
      const result=await request<{public_ipv4:string}>('/v1/wireguard/'+encodeURIComponent(profileId)+'/probe',{method:'POST'});
      const data=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');
      setWgStatuses(data.profiles);
      setMessage('IP público verificado pelo túnel WireGuard: '+result.public_ipv4+'. Nenhuma rota do ASUS foi alterada.');
    }catch(e){setMessage('Verificação de IP não concluída: '+String(e));}
    finally{setBusy(false);}
  }
  async function toggleWireGuard(profileId:string,connect:boolean) {
    setBusy(true);setMessage('');
    try {
      await request('/v1/wireguard/'+encodeURIComponent(profileId)+'/'+(connect?'connect':'disconnect'),{method:'POST'});
      const wg=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');
      setWgStatuses(wg.profiles);
      setMessage(connect?'Interface WireGuard iniciada. O estado Ligado só aparece após um handshake recente. Nenhuma rota de host foi alterada.':'Interface WireGuard desligada.');
    }catch(e){setMessage('Operação WireGuard não concluída: '+String(e));}
    finally{setBusy(false);}
  }
  useEffect(()=>{if(page!=='connections')return;let active=true;const reload=async()=>{try{const data=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');if(active)setWgStatuses(data.profiles);}catch{}};void reload();const timer=setInterval(()=>void reload(),5000);return()=>{active=false;clearInterval(timer);};},[page]);
  useEffect(()=>{if(page!=='connections')return;let active=true;const verify=async()=>{try{const profiles=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');for(const w of profiles.profiles){if(!active)break;if(w.connected){try{await request('/v1/'+(connections.find(c=>c.id===w.id)?.protocol==='openvpn'?'openvpn':'wireguard')+'/'+encodeURIComponent(w.id)+'/probe',{method:'POST'});}catch{}}}if(active){const updated=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');setWgStatuses(updated.profiles);}}catch{}};void verify();const timer=setInterval(()=>void verify(),120000);return()=>{active=false;clearInterval(timer);};},[page]);
  type Neighbor = {ip:string;mac:string;name:string|null;name_source:string|null;state:string[];has_policy:boolean};
  const [neighbors,setNeighbors] = useState<Neighbor[]>([]);
  const [refreshingNeighbors,setRefreshingNeighbors] = useState(false);
  const [discoveryStarted,setDiscoveryStarted] = useState(false);
  const [discoveryError,setDiscoveryError]=useState('');
  const [discoveryFinished,setDiscoveryFinished]=useState(false);
  const [manualHost,setManualHost] = useState(false);
  const [candidateHost,setCandidateHost] = useState('');
  const [hostPlan,setHostPlan] = useState<{hosts:{host_ip:string;eligible:boolean;reason?:string}[];changes_applied:boolean}|null>(null);
  useEffect(()=>{
    if(page!=='policies'||discoveryStarted)return;
    setDiscoveryStarted(true);
    setRefreshingNeighbors(true);
    setDiscoveryFinished(false);
    setDiscoveryError('');
    setNeighbors([]);
    void request<{hosts:Neighbor[];complete:boolean}>('/v1/network/discover',{method:'POST'})
      .then(result=>{
        if(!result.complete)throw new Error('Pesquisa LAN não concluída');
        setNeighbors(result.hosts);
        setDiscoveryFinished(true);
      })
      .catch(()=>{setNeighbors([]);setDiscoveryError('Não foi possível concluir a descoberta. Verifique a LAN configurada.');})
      .finally(()=>setRefreshingNeighbors(false));
  },[page,discoveryStarted]);
  async function loadNetwork() {
    const [t,c] = await Promise.all([request<NetworkTopology>('/v1/network/topology'),request<{draft:NetworkDraft|null;applied:boolean}>('/v1/network/config')]);
    const active = {...t,interfaces:t.interfaces.filter(i=>i.operstate==="UP" && (i.kind==="wifi" || i.kind==="ethernet"))};
    setTopology(active);
    setNetworkDraft(c.draft ? {...c.draft,management_interface:c.draft.management_interface||active.interfaces[0]?.interface||''} : {mode:'shared',management_interface:active.interfaces[0]?.interface||'',wan_webadmin_enabled:false,wan_webadmin_allowed_cidrs:[],interfaces:active.interfaces.map(i=>({interface:i.interface,role:i.interface===active.interfaces[0]?.interface?'lan':'unused',label:''}))});
    setNetworkSaved(Boolean(c.draft));setNetworkApplied(Boolean(c.applied));
  }
  async function saveNetworkDraft() {
    if(!networkDraft)return;
    setBusy(true);
    try {
      await request('/v1/network/config',{method:'PUT',body:JSON.stringify({...networkDraft,wan_webadmin_enabled:false,wan_webadmin_allowed_cidrs:[]})});
      setNetworkSaved(true);setNetworkApplied(false);setMessage('Configuração WAN/LAN guardada.');
      if(confirm('Configuração guardada. Confirmar agora que a topologia corresponde à rede actual? Esta confirmação não altera interfaces, rotas ou firewall.')) { await acceptCurrentNetwork(); } else { setMessage('Configuração guardada, a aguardar confirmação. A rede em execução não foi alterada.'); }
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  async function acceptCurrentNetwork() {
    setBusy(true);setMessage('');
    try {
      const result=await request<{outgoing_interface:string;gateway:string}>('/v1/network/accept-current',{method:'POST'});
      await loadNetwork();
      setMessage('Topologia WAN/LAN confirmada: '+result.outgoing_interface+' → '+result.gateway+'. Não foram alteradas as interfaces, a rota do sistema ou a firewall.');
    }catch(e){setMessage('Não foi possível confirmar WAN/LAN: '+String(e));}
    finally{setBusy(false);}
  }
  async function loadDns() {
    const [config,plan] = await Promise.all([request<{draft:DnsDraft|null}>('/v1/dns/config'),request<DnsPlan>('/v1/dns/isolation-plan')]);
    const draft=config.draft||{enabled:false,upstream_ipv4:[],block_on_vpn_failure:true,lan_only:true};
    setDnsDraft(draft);setDnsServers(draft.upstream_ipv4.join('\n'));setDnsPlan(plan);
    try{setDnsAdmin(await request<DnsAdminStatus>('/v1/dns/admin-status'));}catch{setDnsAdmin(null);}
    try {setDnsLive(await request('/v1/dns/live-dashboard'));}catch {setDnsLive(null);}
    try{setDnsBindings(await request<DnsBindings>('/v1/dns/bindings'));}catch{setDnsBindings(null);}
  }
  async function saveDns() {
    setBusy(true);
    try {const upstream_ipv4=dnsServers.split(/[\s,;]+/).filter(Boolean);await request('/v1/dns/config',{method:'PUT',body:JSON.stringify({...dnsDraft,upstream_ipv4})});await loadDns();setMessage('Rascunho Pi-hole guardado. Serviço DNS não instalado nem activado.');}
    catch(e){setMessage('Configuração DNS rejeitada: '+String(e));}finally{setBusy(false);}
  }
  async function refresh() {
    try {
      try {setLive(await request<Live>('/v1/gateway/live'));}catch{setLive(null);}
      const [a,b] = await Promise.all([request<Connection[]>('/v1/connections'),request<Policy[]>('/v1/policies')]);
      setConnections(a); setPolicies(b);
      try {const wg=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');setWgStatuses(wg.profiles);}catch{setWgStatuses([]);}
      try {await loadNetwork();}catch(e){setMessage('Topologia indisponível: '+String(e));}
      try {setDnsSummary(await request('/v1/dns/summary'));}catch{}
      try {await loadDns();}catch(e){setMessage('Módulo DNS indisponível: '+String(e));}
      const r = await request<Runtime>('/v1/diagnostics/runtime'); setRuntime(r);
      setDirectStatus(null); // Legacy CT102 status disabled on VM210
      setDirectHosts(null); setDirectError('');

    } catch (e) {setMessage(String(e));}
  }
  useEffect(()=>{ void refresh(); },[]);
  useEffect(()=>{
    if(!['monitoring','logs','system'].includes(page))return;
    let mounted=true;
    const load=async()=>{
      try {
        if(page==='monitoring'){const d=await request<{hosts:typeof monitorRows}>('/v1/monitoring/hosts');if(mounted){setMonitorRows(d.hosts);setMonitorSamples(prev=>[...prev,{download:d.hosts.reduce((n,h)=>n+(h.rx_bps??0),0),upload:d.hosts.reduce((n,h)=>n+(h.tx_bps??0),0)}].slice(-36));}}
        if(page==='logs'){const d=await request<{events:typeof eventRows}>('/v1/logs/vpn');if(mounted)setEventRows(d.events);}
        if(page==='system'){const d=await request<{webadmin:string;profiles:number;policies:number;database:string;disk_total_bytes:number;disk_used_bytes:number;services?:{pihole_dns:boolean;vpn_connected:number}}>('/v1/system/health');if(mounted)setHealthSummary(d);}
        if(mounted)setModuleError('');
      }catch(e){if(mounted)setModuleError(String(e));}
    };
    void load();const timer=setInterval(()=>void load(),5000);
    return()=>{mounted=false;clearInterval(timer);};
  },[page]);
  useEffect(()=>{
    if(page!=='diagnostics')return;
    let alive=true;
    const check=async()=>{try{const result=await request<{hosts:typeof diagnosticRows}>('/v1/diagnostics/hosts');if(alive){setDiagnosticRows(result.hosts);setDiagnosticError('');}}catch(e){if(alive)setDiagnosticError(String(e));}};
    void check();const timer=setInterval(()=>void check(),10000);
    return()=>{alive=false;clearInterval(timer);};
  },[page]);
  useEffect(()=>{ if(page!=='overview')return; let mounted=true; const update=async()=>{try{const data=await request<OverviewStatus>('/v1/overview/status');if(mounted){setOverviewStatus(data);setStatusUpdated(new Date().toLocaleTimeString('pt-PT'));const active=data.routes.flatMap(r=>r.hosts).filter(h=>h.status==='gateway_measured');if(active.length){setTrafficHistory(previous=>[...previous,{time:Date.now(),download:active.reduce((n,h)=>n+(h.rx_bps??0),0),upload:active.reduce((n,h)=>n+(h.tx_bps??0),0)}].slice(-45));}}}catch{if(mounted)setOverviewStatus(null);}};void update();const timer=setInterval(()=>void update(),5000);return()=>{mounted=false;clearInterval(timer);}; },[page]);
  useEffect(()=>{if(page!=='policies')return;void loadPolicyRuntime(policies);const timer=setInterval(()=>{void loadPolicyRuntime(policies);void request<Policy[]>('/v1/policies').then(next=>setPolicies(previous=>JSON.stringify(previous)===JSON.stringify(next)?previous:next)).catch(()=>{});},5000);return()=>clearInterval(timer);},[page,policies]);
  async function saveConnection() {
    const finalId=(connection.id||('vpn-'+connection.name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/-+$/,''))).slice(0,32);
    if(!finalId||!connection.name||!connection.provider){setMessage('Preenche o nome e o fornecedor.');return;}
    const existing=connections.find(c=>c.id===finalId);
    const protocol=connection.protocol;
    setBusy(true);setMessage('');
    try {
      if(existing && existing.protocol!==protocol)throw new Error('O protocolo de um perfil existente não pode ser alterado.');
      if(!existing)await request('/v1/connections',{method:'POST',body:JSON.stringify({...connection,id:finalId,protocol,enabled:false})});
      else if(existing.name!==connection.name)await request('/v1/connections/'+encodeURIComponent(finalId),{method:'PUT',body:JSON.stringify({id:finalId,name:connection.name,provider:connection.provider,protocol:existing.protocol,enabled:existing.enabled})});
      if(protocol==='wireguard') {
        const configuration=vpnConfigFile?await vpnConfigFile.text():vpnConfigText.trim();
        if(configuration){
          if(configuration.length>65536)throw new Error('Ficheiro WireGuard excede 64 KiB.');
          await request('/v1/wireguard/import',{method:'POST',body:JSON.stringify({profile_id:finalId,configuration})});
        }else if(!existing){
          setMessage('Perfil criado. Para configurar o túnel, selecciona o ficheiro .conf no mesmo formulário e guarda novamente.');
        }
      } else {
        const raw=vpnConfigFile?new Uint8Array(await vpnConfigFile.arrayBuffer()):new TextEncoder().encode(vpnConfigText.trim());
        if(raw.length){
          if(raw.length>80000)throw new Error('Configuração OpenVPN excede 80 KiB');
          if(!openVpnUsername||!openVpnPassword)throw new Error('Introduza as credenciais OpenVPN do fornecedor');
          let binary='';raw.forEach(byte=>{binary+=String.fromCharCode(byte)});
          await request('/v1/openvpn/import',{method:'POST',body:JSON.stringify({profile_id:finalId,configuration:btoa(binary),username:openVpnUsername,password:openVpnPassword})});
          setOpenVpnUsername('');setOpenVpnPassword('');
        }
      }
      setVpnConfigFile(null);setVpnConfigText('');
      await refresh();
      const wg=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');setWgStatuses(wg.profiles);
      if(protocol==='wireguard'&&(vpnConfigFile||vpnConfigText.trim()))setMessage('Perfil e ficheiro WireGuard guardados. Podes agora ligar o túnel na lista de perfis.');
      else if(protocol!=='wireguard')setMessage(vpnConfigFile||vpnConfigText.trim()?'Configuração OpenVPN e credenciais guardadas no gateway. Pode ligar o perfil.':'Perfil guardado. Importe o ficheiro e as credenciais para ligar.');
    }catch(e){setMessage('Não foi possível guardar a ligação: '+String(e));}
    finally{setBusy(false);}
  }
  async function save(url:string, data:unknown) {
    setBusy(true); setMessage('');
    try { await request(url,{method:'POST',body:JSON.stringify(data)}); await refresh(); setMessage('Configuração guardada em SQLite — sem alterações de rede.'); }
    catch (e) {setMessage(e instanceof Error ? e.message : String(e));}
    finally {setBusy(false);}
  }
  async function loadPolicyRuntime(items:Policy[]) {
    const values=await Promise.all(items.map(async p=>{
      try {return [p.id,await request<{status:string;applied:boolean;deadline?:number;reason?:string}>('/v1/policies/'+encodeURIComponent(p.id)+'/runtime')] as const;}
      catch{return [p.id,{status:'unavailable',applied:false}] as const;}
    }));
    setPolicyRuntime(Object.fromEntries(values));
  }
  async function applyHostAction(id:string,action:'apply'|'confirm'|'rollback') {
    setBusy(true);setMessage('');
    try {
      if(action==='apply' && !confirm('Aplicar temporariamente as regras apenas deste host? Confirme depois de testar a conectividade. Sem confirmação, as regras serão revertidas automaticamente.'))return;
      const result=await request<{status:string;applied:boolean;deadline?:number}>('/v1/policies/'+encodeURIComponent(id)+'/'+action,{method:'POST'});
      await loadPolicyRuntime(policies);
      setMessage(action==='apply'?'Regras temporárias instaladas. Teste agora o cliente e carregue Confirmar antes do prazo de 180 segundos; caso contrário haverá reversão automática.':action==='confirm'?'Política confirmada. Regras activas no anfitrião.':'Regras removidas para este host.');
    }catch(e){setMessage('Não foi possível '+action+': '+String(e));}
    finally{setBusy(false);}
  }
  async function preflightHost(id:string) {
    setBusy(true);setMessage('');
    try {
      const result=await request<{host_ip:string;destination:string;lan_interfaces:string[];wan_interfaces:string[];gateways:{gateway:string}[];ready:boolean;applied:boolean;errors:string[]}>('/v1/policies/'+encodeURIComponent(id)+'/preflight');
      setMessage('Pré-validação de '+result.host_ip+': LAN '+result.lan_interfaces.join(', ')+'; saída '+result.wan_interfaces.join(', ')+'; gateway '+(result.gateways.map(g=>g.gateway).join(', ')||'não detectado')+'. '+(result.errors.length?'Impedimentos: '+result.errors.join('; '):'Sem impedimentos detectados.')+' A política não foi aplicada.');
    }catch(e){setMessage('Pré-validação falhou: '+String(e));}
    finally{setBusy(false);}
  }
  async function removeHostPolicy(p:Policy) {
    if(!confirm('Remover o host '+p.host_ip+' e a sua regra de encaminhamento?\n\nA remoção deixa de proteger este host pela VPN ou pelo bloqueio; poderá usar o gateway predefinido da rede.'))return;
    setBusy(true);
    try {
      if(!['direct','blocked'].includes(p.destination)){
        await request('/v1/policies/'+encodeURIComponent(p.id)+'/transition-vpn?destination=direct',{method:'POST'});
      }
      await request('/v1/policies/'+encodeURIComponent(p.id),{method:'DELETE'});
      await refresh();
      setMessage('Host '+p.host_ip+' removido; política e regras eliminadas.');
    }catch(e){
      await refresh();
      setMessage('Falha ao remover o host '+p.host_ip+': '+String(e)+'. Verifique a rota efectiva.');
    }finally{setBusy(false);}
  }
  async function activateRestoredHost(id:string,destination:string) {
    setBusy(true);
    try {
      await request('/v1/policies/'+encodeURIComponent(id)+'/activate-restored',{method:'POST'});
      await refresh();
      setMessage(language==='pt'?'Host protegido em BLOQUEADO. Ligue a VPN e escolha Editar → Aplicar para concluir a associação.':'Host protected in BLOCKED mode. Connect the VPN, then choose Edit → Apply to complete association.');
    } catch(e) {setMessage(String(e));} finally {setBusy(false);}
  }
  async function changeHostRoute(id:string,destination:string) {
    const existing=policies.find(p=>p.id===id);
    if(!existing)return;
    setBusy(true);
    try {
      if(['direct','blocked'].includes(existing.destination)&&['direct','blocked'].includes(destination)){
        await request('/v1/policies/'+encodeURIComponent(id)+'/transition-basic?destination='+encodeURIComponent(destination),{method:'POST'});
        await refresh();setMessage('Rota '+destination.toUpperCase()+' aplicada e confirmada no gateway para '+existing.host_ip+'.');
      } else {
        const result=await request<{confirmation_required:boolean;deadline?:number;policy:Policy}>('/v1/policies/'+encodeURIComponent(id)+'/transition-vpn?destination='+encodeURIComponent(destination),{method:'POST'});
        await refresh();setMessage(result.confirmation_required?'VPN aplicada ao host '+existing.host_ip+'. Teste a Internet/DNS e clique em Confirmar VPN nos próximos 180 segundos; caso contrário, a rota anterior será restaurada.':'Transição aplicada e confirmada pelo gateway para '+existing.host_ip+'.');
      }
      return true;
    }
    catch(e){setMessage(e instanceof Error?e.message:String(e));return false;}
    finally{setBusy(false);}
  }
  async function removeConnection(id:string) {
    const profile=connections.find(c=>c.id===id);
    const attached=policies.filter(p=>p.destination===id).map(p=>p.host_ip);
    if(attached.length){setMessage('Não é possível eliminar: perfil associado a '+attached.join(', ')+'. Remova primeiro as políticas em Hosts e rotas.');return;}
    if(!confirm('Eliminar o perfil VPN «'+(profile?.name||id)+'»? Esta acção não pode ser anulada.'))return;
    setBusy(true);
    try {await request('/v1/connections/'+encodeURIComponent(id),{method:'DELETE'});await refresh();setMessage('Perfil VPN eliminado.');}
    catch(e){setMessage(e instanceof Error?e.message:String(e));}
    finally{setBusy(false);}
  }
  async function remove(id:string) {
    if (!confirm('Eliminar esta política guardada?')) return;
    setBusy(true);
    try {await request('/v1/policies/'+encodeURIComponent(id),{method:'DELETE'});await refresh();setMessage('Política removida.');}
    catch(e){setMessage(String(e));} finally{setBusy(false);}
  }
  async function testDirect() {
    setTestingDirect(true); setMessage('');
    try {setDirect(await request<DirectProbe>('/v1/diagnostics/direct'));}
    catch(e) {setMessage(String(e));}
    finally {setTestingDirect(false);}
  }
  const nav: [Page,MenuIconName,string][] = [['overview','home','Visão geral'],['network','network','Rede WAN/LAN'],['dns','shield','Pi-hole DNS'],['connections','lock','Ligações VPN'],['policies','route','Hosts e rotas'],['diagnostics','diagnostic','Diagnóstico'],['monitoring','monitor','Monitorização'],['logs','logs','Registos'],['system','settings','Sistema']];
  return <div className="layout">
    <aside className="sidebar"><div className="brand"><img className="brand-shield" src="/favicon.ico" alt="Escudo português"/><div><strong>Gateway VPN Multi</strong><small>Gestão de rede e privacidade</small></div></div><div className="navlabel">ADMINISTRAÇÃO</div>
      <nav>{nav.map(([key,ic,name])=><button key={key} className={page===key?'navitem active':'navitem'} onClick={()=>setPage(key)}><span className="nav-icon"><MenuIcon name={ic}/></span>{name}</button>)}</nav>

    </aside>
    <div className="main"><header className="topbar"><div><span className="breadcrumb">GATEWAY / {nav.find(x=>x[0]===page)?.[2]}</span><h1>{nav.find(x=>x[0]===page)?.[2]}</h1>{page==='overview'&&<p className="overview-subtitle">Estado do sistema, ligações e encaminhamentos</p>}</div><div className="topactions"><label className="global-language"><span>{t.language}</span><select aria-label={t.language} value={language} onChange={e=>setLanguage(e.target.value as 'pt'|'en')}><option value="pt">PT</option><option value="en">EN</option></select></label><span className="tag">Instalada: v{overviewStatus?.installed_version||'0.0.1'}</span>{overviewStatus?.latest_version&&overviewStatus.latest_version!==overviewStatus.installed_version&&<span className="tag">Nova versão: v{overviewStatus.latest_version}</span>}</div></header>
    {message&&page!=='overview'&&<div role="status" className="flash">{message}</div>}
    {page==='overview'&&<div className="dashboard-overview">
      <div className="dashboard-cards">
        <div className="dashboard-kpi green"><span className="kpi-icon">◈</span><div><strong>Ligações VPN</strong><b>{overviewStatus?.services?.vpn_connected??"—"}</b><small>Túneis activos confirmados</small></div></div>
        <div className="dashboard-kpi blue"><span className="kpi-icon">▣</span><div><strong>Hosts no Gateway</strong><b>{overviewStatus?.routes.reduce((n,r)=>n+r.hosts.length,0)??0}</b><small>Hosts com política configurada</small></div></div>
        <div className="dashboard-kpi gold"><span className="kpi-icon">⇄</span><div><strong>Saída directa</strong><b>{overviewStatus?.routes.find(r=>r.id==='direct')?.hosts.length??0}</b><small>Políticas DIRECT configuradas</small></div></div>
        <div className="dashboard-kpi purple"><span className="kpi-icon">⇆</span><div><strong>Rotas disponíveis</strong><b>{overviewStatus?.routes.filter(r=>r.available).length??'—'}</b><small>Saídas configuradas</small></div></div>
      </div>
      <section className="dashboard-section"><div className="dashboard-section-title"><h2>✦ &nbsp; Serviços do Gateway</h2></div><div className="service-grid">
        <div className="service-card"><span className="service-symbol">▦</span><div><strong>WebAdmin</strong><p className="service-up">● Em execução</p><small>v{overviewStatus?.installed_version||'0.0.1'}</small></div><span className="service-port">HTTPS<br/>443</span></div>
        <div className="service-card"><span className="service-symbol">◉</span><div><strong>Pi-hole</strong><p className={overviewStatus?.services?.pihole_dns?"service-up":"service-unknown"}>{overviewStatus?.services?.pihole_dns?"● DNS operacional":overviewStatus?"DNS indisponível":"A verificar DNS"}</p><small>Estado do serviço DNS · verificado na API</small></div></div>
        <div className="service-card"><span className="service-symbol">⚿</span><div><strong>VPNs (WireGuard / OpenVPN)</strong><p className={overviewStatus?.services?.vpn_connected?"service-up":"service-unknown"}>{overviewStatus?.services?.vpn_connected!==undefined?"● "+overviewStatus.services.vpn_connected+" de "+overviewStatus.services.vpn_tunnels.length+" túnel(is) ligado(s)":"A verificar VPN"}</p>{overviewStatus?.services?.vpn_tunnels.map(t=><small key={t.id} style={{display:'block'}}>{t.connected?'● Ligado':'○ Desligado'} · {t.name} ({t.protocol==='wireguard'?'WireGuard':'OpenVPN'}){t.interface?' · '+t.interface:''}</small>)}</div></div>
      </div></section>
      <section className="dashboard-section"><div className="dashboard-section-title"><h2>◉ &nbsp; Estado das rotas e consumo</h2><span className="dashboard-pill">Actualização: 5 s · {statusUpdated||'a aguardar'}</span></div>
        {(()=>{const measured=overviewStatus?.routes.flatMap(r=>r.hosts).filter(h=>h.status==='gateway_measured'&&h.rx_bytes!==null&&h.tx_bytes!==null)??[];const down=measured.reduce((n,h)=>n+(h.rx_bytes??0),0);const up=measured.reduce((n,h)=>n+(h.tx_bytes??0),0);const fmt=(bytes:number)=>(bytes/1048576).toLocaleString('pt-PT',{maximumFractionDigits:2,minimumFractionDigits:2})+' MB';const maximum=Math.max(1,...trafficHistory.map(p=>Math.max(p.download,p.upload)));const points=(key:'download'|'upload')=>trafficHistory.map((p,i)=>(i*600/Math.max(1,trafficHistory.length-1)).toFixed(1)+','+(132-p[key]*119/maximum).toFixed(1)).join(' ');return <div className="traffic-content"><div className="traffic-donut"><div className="traffic-ring" style={measured.length?{borderColor:'#17db83'}:undefined}><div><strong>{measured.length?fmt(down+up):'—'}</strong><small>Tráfego acumulado</small></div></div><div className="traffic-legend"><p><i className="legend-dot down"/> Download <strong>{measured.length?fmt(down):'Não medido'}</strong></p><p><i className="legend-dot up"/> Upload <strong>{measured.length?fmt(up):'Não medido'}</strong></p><p><i className="legend-dot total"/> Total <strong>{measured.length?fmt(down+up):'Não medido'}</strong></p><small className="traffic-note">Consumo acumulado por host e rota, persistente após reinício; exclui tráfego do gateway.</small></div></div><div className="traffic-graph"><h3>{language==='en'?'Forwarded traffic speed · last ':'Velocidade de tráfego encaminhado · últimos '}{trafficHistory.length*5}{language==='en'?' seconds':' segundos'}</h3>{trafficHistory.length>=2?<><svg className="traffic-chart" viewBox="0 0 600 152" preserveAspectRatio="none" role="img" aria-label="Histórico de velocidades de download e upload"><line x1="0" y1="132" x2="600" y2="132" stroke="#354d57"/><line x1="0" y1="72" x2="600" y2="72" stroke="#29404a" strokeDasharray="4 7"/><polyline points={points('download')} stroke="#17db83" strokeWidth="2.5" fill="none" vectorEffect="non-scaling-stroke"/><polyline points={points('upload')} stroke="#309df3" strokeWidth="2.5" fill="none" vectorEffect="non-scaling-stroke"/></svg><div className="traffic-chart-labels"><span>Download {((trafficHistory[trafficHistory.length-1].download)/1000000).toFixed(2)} Mbps</span><span>Upload {((trafficHistory[trafficHistory.length-1].upload)/1000000).toFixed(2)} Mbps</span></div></>:<div className="graph-placeholder">{measured.length?'A recolher amostras de velocidade…':'Sem contadores reais disponíveis'}</div>}</div></div>;})()}
      </section>
      <section className="dashboard-section"><div className="dashboard-section-title"><h2>◉ &nbsp; Rotas disponíveis</h2></div><div className="tablewrap"><table className="dashboard-table"><thead><tr><th>#</th><th>Nome</th><th>Tipo</th><th>Transporte</th><th>Estado</th><th>Hosts configurados</th><th>Download</th><th>Upload</th><th>Total</th></tr></thead><tbody>{overviewStatus?.routes.map((r,i)=><tr key={r.id}><td>{i+1}</td><td>◎ &nbsp; {r.name}</td><td><span className="route-type">{r.id==='direct'?'DIRECT':r.id==='blocked'?'BLOQUEADO':connections.find(c=>c.id===r.id)?.protocol==='wireguard'?'VPN WireGuard':connections.find(c=>c.id===r.id)?.protocol==='openvpn'?'VPN OpenVPN':'VPN'}</span></td><td>{r.id==='direct'||r.id==='blocked'?'—':(wgStatuses.find(w=>w.id===r.id)?.transport||'Não verificado')}</td><td><span className={r.active?'route-active':'route-pending'}>{r.active?'● Activa':connections.some(c=>c.id===r.id&&c.protocol==='wireguard'&&c.configuration_stored)?'Desligada':r.available?'Disponível':'Indisponível'}</span></td><td>{r.hosts.length}</td><td>{r.rx_bps===null?'—':(r.rx_bps/1000000).toFixed(2)+' Mbps'}</td><td>{r.tx_bps===null?'—':(r.tx_bps/1000000).toFixed(2)+' Mbps'}</td><td>{r.hosts.some(h=>h.rx_bytes!==null&&h.tx_bytes!==null)?((r.hosts.reduce((n,h)=>n+(h.rx_bytes||0)+(h.tx_bytes||0),0))/1048576).toFixed(2)+' MB':r.hosts.length===0?'Sem hosts':'Não medido'}</td></tr>)}</tbody></table></div></section>
      <section className="dashboard-section"><div className="dashboard-section-title"><h2>♧ &nbsp; Hosts configurados no gateway</h2></div><div className="tablewrap"><table className="dashboard-table"><thead><tr><th>IP</th><th>Rota</th><th>Download</th><th>Upload</th><th>Total</th><th>Vel. download</th><th>Vel. upload</th><th>Estado</th></tr></thead><tbody>{overviewStatus?.routes.flatMap(r=>r.hosts.map(h=><tr key={r.id+'-'+h.ip}><td>{h.ip}</td><td>{r.name}</td><td>{h.rx_bytes===null?'—':(h.rx_bytes/1048576).toFixed(2)+' MB'}</td><td>{h.tx_bytes===null?'—':(h.tx_bytes/1048576).toFixed(2)+' MB'}</td><td>{h.rx_bytes===null||h.tx_bytes===null?'—':((h.rx_bytes+h.tx_bytes)/1048576).toFixed(2)+' MB'}</td><td>{h.rx_bps===null?'—':(h.rx_bps/1000000).toFixed(2)+' Mbps'}</td><td>{h.tx_bps===null?'—':(h.tx_bps/1000000).toFixed(2)+' Mbps'}</td><td>{(()=>{const p=policies.find(p=>p.host_ip===h.ip);const observed=discoveryFinished?neighbors.find(n=>n.ip===h.ip):undefined;const unauthorized=h.authorization_status==="unauthorized";return unauthorized?<span className="route-pending" style={{color:'#fb7185',fontWeight:700}}>● Erro — Host não autorizado</span>:h.status==='gateway_measured'?<span className="route-active">● Medido</span>:<span className={h.status==="active"?"route-active":"route-pending"}>{h.status==="active"?"● Activo · sem medição":h.status==="vpn_trial"?"● VPN em teste · reversão automática":h.status==="pending"?"A aguardar confirmação":h.status==="reverted"?"Revertido":h.status==="vpn_disconnected"?"VPN desligada no WebAdmin":h.status==="provider_handshake"?"VPN sem handshake · verificar fornecedor":h.status==="routing_failure"?"Falha no encaminhamento protegido":h.status==="unknown_vpn"?"VPN não identificada":h.status==="error"?"Erro de política":"Rascunho · não aplicado"}</span>})()}</td></tr>))}{!overviewStatus?.routes.some(r=>r.hosts.length>0)&&<tr><td colSpan={8} className="dashboard-empty">Ainda não existem hosts com políticas configuradas.</td></tr>}</tbody></table></div></section>
    </div>}
    {page==='network'&&topology&&networkDraft&&<section className="panel">
      <div className="panelhead"><h2>Topologia WAN / LAN</h2><span className="softtag">{networkDraft.mode==='shared'?'Interface partilhada':'WAN e LAN separadas'} · rascunho</span></div>
      {(()=>{
        const shared=networkDraft.mode==='shared';
        const lan=networkDraft.interfaces.filter(i=>i.role==='lan');
        const wan=networkDraft.interfaces.find(i=>i.role==='wan');
        const observed=(name:string)=>topology.interfaces.find(i=>i.interface===name);
        const address=(i:NetworkDraft['interfaces'][number])=>i.ipv4_address&&i.prefix_length!=null?i.ipv4_address+'/'+i.prefix_length:observed(i.interface)?.network||'IP por configurar';
        const uplink=shared?networkDraft.management_interface:wan?.interface;
        const route=topology.default_routes.find(r=>r.interface===uplink);
        const gateway=shared?route?.gateway:wan?.address_mode==='static'?wan.gateway_ipv4:route?.gateway;
        return <div className="topology-layout">
          <div className="topology-step"><span>{shared?'LIGAÇÃO À INTERNET · REDE PARTILHADA':'ENTRADA / INTERNET · WAN'}</span><strong>{uplink||'Interface WAN por seleccionar'}</strong><small>{!shared&&wan?.address_mode==='static'?'IPv4 estático':!shared?'DHCP / endereço automático':'WAN/LAN na mesma interface'}</small><small>{shared?(observed(uplink||'')?.network||'Rede actual não detectada'):wan?address(wan):'—'}</small><small>Gateway: {gateway||'Por detectar/configurar'}</small></div>
          <span className="topology-arrow">→</span>
          <div className="topology-step topology-gateway"><span>GATEWAY VPN MULTI</span><strong>{shared?'WAN + LAN partilhadas':'Encaminhamento WAN → LAN'}</strong><small>Gestão: {networkDraft.management_interface}</small><small>{observed(networkDraft.management_interface)?.address||'IP de gestão por configurar'}</small></div>
          <span className="topology-arrow">→</span>
          <div className="topology-outputs">
            {lan.map(i=><div className="topology-step" key={i.interface}><span>LAN / CLIENTES · {i.address_mode==='dhcp'?'DHCP não permitido':'IP ESTÁTICO'}</span><strong>{i.interface}</strong><small>{address(i)}</small></div>)}
            <div className="topology-step topology-management"><span>ACESSO ADMINISTRATIVO</span><strong>WebAdmin</strong><small>{networkDraft.management_interface} · {observed(networkDraft.management_interface)?.address||'IP por configurar'}</small></div>
          </div>
        </div>;
      })()}
      <p className="muted">Diagrama conforme a modalidade e as interfaces seleccionadas na configuração inicial. Os valores propostos podem diferir da rede em execução. Guardar não altera interfaces, gateway, DNS ou firewall.</p>
    </section>}
    {page==='network'&&<section className="panel"><div className="panelhead"><h2>Interfaces WAN / LAN</h2><span className="softtag">Configuração da rede</span></div><p className="muted">Seleccione as interfaces físicas e as respectivas funções. Nesta versão, guardar cria apenas um rascunho; confirmar valida a topologia existente, sem modificar a rede.</p>{topology&&networkDraft?<><div className="formgrid"><label>Modo de instalação<select value={networkDraft.mode} onChange={e=>{setNetworkSaved(false);setNetworkDraft({...networkDraft,mode:e.target.value as NetworkDraft['mode'],interfaces:e.target.value==='shared'?networkDraft.interfaces.map(x=>({...x,role:x.interface===networkDraft.management_interface?'lan':'unused'})):networkDraft.interfaces,wan_webadmin_enabled:e.target.value==='shared'?false:networkDraft.wan_webadmin_enabled,wan_webadmin_allowed_cidrs:e.target.value==='shared'?[]:networkDraft.wan_webadmin_allowed_cidrs});}}><option value="shared">Uma interface · LAN partilhada</option><option value="routed" disabled={topology.interfaces.filter(i=>i.kind==='ethernet'||i.kind==='wifi').length<2}>WAN + LAN separadas (mín. 2 interfaces físicas)</option><option value="multi_lan" disabled={topology.interfaces.filter(i=>i.kind==='ethernet'||i.kind==='wifi').length<3}>WAN + várias LANs (mín. 3 interfaces físicas)</option></select></label></div>{topology.interfaces.map(i=><div className="check" key={i.interface}><strong>{i.interface}</strong> · {i.address} · {i.network} · {i.operstate} {i.default_route?'· rota padrão':''}<div className="formgrid"><label>Função<select disabled={networkDraft.mode==='shared'} value={networkDraft.mode==='shared'?(i.interface===networkDraft.management_interface?'lan':'unused'):networkDraft.interfaces.find(x=>x.interface===i.interface)?.role||'unused'} onChange={e=>{setNetworkSaved(false);setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,role:e.target.value as 'wan'|'lan'|'unused'}:x)});}}><option value="unused">Não utilizada</option><option value="wan">WAN / ISP</option><option value="lan">LAN / Clientes</option></select></label><label>Descrição<input value={networkDraft.interfaces.find(x=>x.interface===i.interface)?.label||''} maxLength={64} placeholder="Ex.: ISP principal / Rede escritório" onChange={e=>{setNetworkSaved(false);setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,label:e.target.value}:x)});}}/></label></div></div>)}{networkDraft.mode!=='shared'&&networkDraft.interfaces.filter(i=>i.role!=='unused').map(i=><div className="check" key={'address-'+i.interface}><strong>{i.role==='lan'?'LAN — IPv4 estático obrigatório':'WAN — configuração IPv4'} · {i.interface}</strong><div className="formgrid"><label>Tipo de endereço<select disabled={i.role==='lan'} value={i.role==='lan'?'static':i.address_mode||'dhcp'} onChange={e=>setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,address_mode:e.target.value as 'static'|'dhcp',ipv4_address:null,prefix_length:null,gateway_ipv4:null,dns_ipv4:[]}:x)})}><option value="static">IP estático</option>{i.role==='wan'&&<option value="dhcp">DHCP (automático)</option>}</select></label>{(i.role==='lan'||i.address_mode==='static')&&<><label>Endereço IPv4<input required placeholder="IPv4 da interface" value={i.ipv4_address||''} onChange={e=>setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,address_mode:'static',ipv4_address:e.target.value}:x)})}/></label><label>Prefixo CIDR<input required type="number" min="1" max="32" placeholder="24" value={i.prefix_length??''} onChange={e=>setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,address_mode:'static',prefix_length:e.target.value?Number(e.target.value):null}:x)})}/></label>{i.role==='wan'&&<><label>Gateway IPv4<input required placeholder="IPv4 do gateway" value={i.gateway_ipv4||''} onChange={e=>setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,gateway_ipv4:e.target.value}:x)})}/></label><label>Servidores DNS IPv4 (separados por vírgulas)<input placeholder="1.1.1.1, 9.9.9.9" value={(i.dns_ipv4||[]).join(', ')} onChange={e=>setNetworkDraft({...networkDraft,interfaces:networkDraft.interfaces.map(x=>x.interface===i.interface?{...x,dns_ipv4:e.target.value.split(',').map(s=>s.trim()).filter(Boolean)}:x)})}/></label></>}</>}</div><small>Esta configuração é um rascunho e não altera endereços, rotas nem DNS do sistema.</small></div>)} <div className="formgrid"><label>Interface de gestão do WebAdmin<select disabled={networkDraft.mode==='shared'} value={networkDraft.management_interface} onChange={e=>{if(networkDraft.interfaces.find(x=>x.interface===e.target.value)?.role!=='lan')return;setNetworkSaved(false);setNetworkDraft({...networkDraft,management_interface:e.target.value});}}>{topology.interfaces.filter(i=>networkDraft.interfaces.find(x=>x.interface===i.interface)?.role==='lan').map(i=><option key={i.interface} value={i.interface}>{i.interface} · {i.address}</option>)}</select></label></div>{networkDraft.interfaces.find(i=>i.interface===networkDraft.management_interface)?.role!=='lan'&&<div className="check"><strong>Configuração inválida:</strong> a interface de gestão do WebAdmin deve ter a função LAN / Clientes. Seleccione outra interface de gestão ou altere a função desta para LAN.</div>}<button className="button" disabled={busy || networkDraft.interfaces.find(i=>i.interface===networkDraft.management_interface)?.role!=='lan'} onClick={()=>void saveNetworkDraft()}>Guardar</button> <span className="softtag">{networkApplied?'Configuração confirmada':networkSaved?'Guardada · a aguardar confirmação':'Alterações por guardar'}</span></>:<p className="muted">A carregar interfaces…</p>}</section>}
    {page==='dns'&&<>
      <section className="panel"><div className="panelhead"><h2>Dashboard Pi-hole</h2><span className="softtag">Estatísticas reais · Pi-hole principal</span></div>
      <div className="cards four">
        <div className="stat"><span>Consultas DNS</span><b>{dnsLive?.stats?.total.toLocaleString('pt-PT')??'—'}</b><small>{dnsLive?.stats?.active_clients??'—'} clientes activos</small></div>
        <div className="stat"><span>Consultas bloqueadas</span><b>{dnsLive?.stats?.blocked.toLocaleString('pt-PT')??'—'}</b><small>Filtragem do Pi-hole principal</small></div>
        <div className="stat"><span>Percentagem bloqueada</span><b>{dnsLive?.stats?dnsLive.stats.percent_blocked.toLocaleString('pt-PT',{maximumFractionDigits:1})+'%':'—'}</b><small>Consultas bloqueadas / total</small></div>
        <div className="stat"><span>Domínios nas listas</span><b>{dnsLive?.stats?.domains.toLocaleString('pt-PT')??'—'}</b><small>Listas centralizadas</small></div>
      </div><p className="muted">Dados recolhidos do Pi-hole principal. O resolvedor VPN tem cache e estatísticas próprias; os seus pedidos não estão incluídos nestes totais. {dnsLive?.stats?'Consultas em cache no principal: '+dnsLive.stats.cached.toLocaleString('pt-PT')+'.':'Estatísticas indisponíveis.'}</p>
      </section>
      <section className="panel"><div className="panelhead"><h2>Serviço e administração</h2><span className="softtag">Pi-hole v{dnsSummary?.version||'—'}</span></div>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:20,flexWrap:"wrap",padding:"22px 24px"}}><div><strong>Pi-hole</strong><p className={dnsLive?.primary_dns?"service-up":"service-unknown"}>{dnsLive?.primary_dns?"● Operacional":"Estado não confirmado"}</p><small>{`DNS · ${window.location.hostname}:53`}</small></div><a className="button" href={`https://${window.location.hostname}:8443/admin/`} target="_blank" rel="noopener noreferrer">Abrir administração Pi-hole ↗</a></div>
      </section>
    </>}
    {page==='connections'&&<><section className="panel vpn-summary-panel"><div className="panelhead"><h2>Resumo das ligações VPN</h2><span className="softtag">Estado real · actualização 5 s</span></div>
{connections.length?<div className="cards three">{connections.map(c=>{const w=wgStatuses.find(x=>x.id===c.id);const assigned=overviewStatus?.routes.find(r=>r.id===c.id)?.hosts||[];const fmt=(n:number|null|undefined)=>n==null?'Não medido':n>=1048576?(n/1048576).toFixed(2)+' MB':n>=1024?(n/1024).toFixed(1)+' KB':n+' B';return <div className="stat" key={c.id}><span>{c.name} · {c.protocol.toUpperCase()}</span><b className={w?.connected?'vpn-ok':''}>{w?.connected?'● Ligado':w?.tunnel_active?'● A aguardar handshake':w?'● Desligado':'● Não verificado'}</b><small>{c.provider} · {assigned.length} host(s) nesta VPN</small><p>Interface: {w?.interface_name||'—'} · Transporte: {w?.transport||'—'}</p><p>Recebido: {fmt(w?.received_bytes)} · Enviado: {fmt(w?.sent_bytes)}</p><p>IP público: {w?.public_ipv4||'Não verificado'}</p><small>Protecção por host: {assigned.length?'Gerida nas políticas e firewall dos hosts':'Sem hosts associados'}.</small></div>;})}</div>:<p className="muted">Nenhuma ligação VPN configurada.</p>}
</section><div className="cards three"><div className="stat"><span>Perfis</span><b>{connections.length}</b></div><div className="stat"><span>Túneis ligados</span><b>{wgStatuses.filter(w=>w.connected).length}</b><small>Handshakes WireGuard recentes</small></div><div className="stat"><span>Hosts em VPN</span><b>{overviewStatus?.routes.filter(r=>r.id!=='direct'&&r.id!=='blocked').reduce((n,r)=>n+r.hosts.length,0)??0}</b><small>Políticas efectivas no gateway</small></div></div><section className="panel"><div className="panelhead"><h2>Perfis VPN</h2><span className="softtag">WireGuard / OpenVPN</span></div>{connections.length?<div className="tablewrap"><table><thead><tr><th>Nome</th><th>Fornecedor</th><th>Protocolo</th><th>Estado</th><th>Acções</th></tr></thead><tbody>{connections.map(c=><tr key={c.id}><td><strong>{c.name}</strong><small>{c.id}</small></td><td>{c.provider}</td><td>{c.protocol.toUpperCase()}</td><td><span className={"status "+(wgStatuses.find(w=>w.id===c.id)?.tunnel_active?"active":"pending")}>{c.protocol==='wireguard'?(wgStatuses.find(w=>w.id===c.id)?.connected?'Ligado · handshake recente':wgStatuses.find(w=>w.id===c.id)?.tunnel_active?'Interface activa · a aguardar handshake':wgStatuses.find(w=>w.id===c.id)?.format_valid?'Configurado · desligado':wgStatuses.find(w=>w.id===c.id)?.stored?'Ficheiro inválido':'A aguardar importação .conf'):(wgStatuses.find(w=>w.id===c.id)?.connected?'Ligado':wgStatuses.find(w=>w.id===c.id)?.tunnel_active?'A estabelecer ligação':wgStatuses.find(w=>w.id===c.id)?.format_valid?'Configurado · desligado':'A aguardar importação .ovpn e credenciais')}</span></td><td>{c.protocol==='wireguard'&&<button type="button" className="button secondary" disabled={busy||(!wgStatuses.find(w=>w.id===c.id)?.tunnel_active&&!wgStatuses.find(w=>w.id===c.id)?.format_valid)} title={wgStatuses.find(w=>w.id===c.id)?.tunnel_active&&overviewStatus?.routes.find(r=>r.id===c.id)?.hosts.length?'Ao desligar, os hosts associados ficam sem Internet se tiverem kill switch validado; caso contrário o servidor recusa':!wgStatuses.find(w=>w.id===c.id)?.format_valid?'Importe primeiro o ficheiro .conf válido':'Controlar ligação WireGuard'} onClick={()=>{const connected=Boolean(wgStatuses.find(w=>w.id===c.id)?.tunnel_active);if(confirm((connected?'Desligar':'Ligar')+' a VPN '+c.name+'?'))void toggleWireGuard(c.id,!connected);}}>{wgStatuses.find(w=>w.id===c.id)?.tunnel_active?'Desligar':'Ligar'}</button>}{c.protocol==='openvpn'&&<button type="button" className="button secondary" disabled={busy||(!wgStatuses.find(w=>w.id===c.id)?.tunnel_active&&!wgStatuses.find(w=>w.id===c.id)?.format_valid)} onClick={async()=>{const active=Boolean(wgStatuses.find(w=>w.id===c.id)?.tunnel_active);if(!confirm((active?'Desligar':'Ligar')+' '+c.name+'?'))return;setBusy(true);try{await request('/v1/openvpn/'+encodeURIComponent(c.id)+'/'+(active?'disconnect':'connect'),{method:'POST'});const data=await request<{profiles:WgProfileStatus[]}>('/v1/wireguard/profiles/status');setWgStatuses(data.profiles);setMessage('Comando OpenVPN executado: '+c.name);}catch(e){setMessage('OpenVPN: '+String(e));}finally{setBusy(false)}}}>{wgStatuses.find(w=>w.id===c.id)?.tunnel_active?'Desligar':'Ligar'}</button>} <button type="button" className="button secondary" disabled={busy||Boolean(overviewStatus?.routes.find(r=>r.id===c.id)?.hosts.length)||Boolean(wgStatuses.find(w=>w.id===c.id)?.tunnel_active)||policies.some(p=>p.destination===c.id)||c.enabled} title={policies.some(p=>p.destination===c.id)?'Perfil associado a hosts: remova primeiro as políticas em Hosts e rotas':c.enabled?'Desactive primeiro o perfil':'Eliminar perfil'} onClick={()=>void removeConnection(c.id)}>Eliminar</button></td></tr>)}</tbody></table></div>:<div className="empty">Nenhum perfil criado. Adicione um perfil para começar a desenhar as políticas.</div>}</section>{selectedVpnLog&&<section className="panel"><div className="panelhead"><h2>Registos VPN · {connections.find(c=>c.id===selectedVpnLog)?.name||selectedVpnLog}</h2><span className="softtag">Histórico individual · até 100 eventos</span></div><div className="tablewrap"><table><thead><tr><th>Data / hora</th><th>Evento</th><th>Detalhes</th></tr></thead><tbody>{vpnEvents.map((e,i)=><tr key={e.at+'-'+i}><td>{new Date(e.at).toLocaleString('pt-PT')}</td><td>{e.event}</td><td>{e.detail}</td></tr>)}{vpnEvents.length===0&&<tr><td colSpan={3}>Ainda sem eventos registados para esta ligação. O histórico começa após esta actualização.</td></tr>}</tbody></table></div></section>}<section className="panel"><div className="panelhead"><h2>Perfis de ligação</h2></div><form className="formgrid" onSubmit={e=>{e.preventDefault();void saveConnection();}}><h3 className="vpn-form-title">Criar ou configurar ligação VPN</h3><label>Perfil existente (opcional)<select value={connections.some(c=>c.id===connection.id)?connection.id:''} onChange={e=>{const found=connections.find(c=>c.id===e.target.value);setConnection(found?{id:found.id,name:found.name,provider:found.provider,protocol:found.protocol}:{id:'',name:'',provider:'',protocol:'wireguard'});setVpnConfigFile(null);setVpnConfigText('');}}><option value="">Criar nova ligação…</option>{connections.map(c=><option key={c.id} value={c.id}>{c.name} · {c.protocol.toUpperCase()}</option>)}</select></label><label>Nome da ligação<input required placeholder="Ex.: Portugal VPN" value={connection.name} onChange={e=>setConnection({...connection,name:e.target.value})}/></label><label>Fornecedor<select required value={connection.provider} onChange={e=>setConnection({...connection,provider:e.target.value})}><option value="">Seleccionar fornecedor…</option><option value="CyberGhost">CyberGhost</option><option value="Proton VPN">Proton VPN</option><option value="Outro">Outro / configuração própria</option></select></label><label>Protocolo<select value={connection.protocol} onChange={e=>setConnection({...connection,protocol:e.target.value as 'wireguard'|'openvpn'})}><option value="wireguard">WireGuard</option><option value="openvpn">OpenVPN</option></select></label>{connection.protocol==='openvpn'&&<><label>Utilizador OpenVPN<input autoComplete="username" placeholder={connection.provider==='Proton VPN'?'Utilizador OpenVPN / IKEv2 (não o email da conta)':connection.provider==='CyberGhost'?'Utilizador das credenciais manuais do CyberGhost':'Utilizador fornecido pelo serviço VPN'} value={openVpnUsername} onChange={e=>setOpenVpnUsername(e.target.value)}/></label><label>Palavra-passe OpenVPN<input type="password" autoComplete="new-password" placeholder="Palavra-passe da configuração OpenVPN" value={openVpnPassword} onChange={e=>setOpenVpnPassword(e.target.value)}/></label><p className="muted vpn-form-wide">{connection.provider==='Proton VPN'?'Proton VPN: utilizar as credenciais OpenVPN/IKEv2 geradas na conta, diferentes das credenciais de início de sessão.':connection.provider==='CyberGhost'?'CyberGhost: utilizar as credenciais da configuração manual OpenVPN disponibilizadas pelo fornecedor.':'Utilize as credenciais específicas de OpenVPN disponibilizadas pelo seu fornecedor.'} As credenciais são transmitidas por HTTPS e guardadas no ASUS com permissões restritas, separadas da interface. Não aparecem após guardar.</p></>}{connection.protocol==='wireguard'&&<p className="muted vpn-form-wide">WireGuard utiliza chaves e um ficheiro de configuração, não utilizador e palavra-passe. A importação segura ficará associada ao perfil.</p>}<div className="vpn-form-wide"><label>{connection.provider==='CyberGhost'?'Ficheiro ZIP de configuração CyberGhost':connection.protocol==='wireguard'?'Ficheiro de configuração WireGuard (.conf)':'Ficheiro de configuração OpenVPN (.ovpn ou .conf)'}<input type="file" accept={connection.provider==='CyberGhost'?'.zip,application/zip':connection.protocol==='wireguard'?'.conf,text/plain':'.ovpn,.conf,text/plain'} onChange={e=>{setVpnConfigFile(e.target.files?.[0]||null);setVpnConfigText('')}}/></label>{vpnConfigFile&&<p className="muted">Seleccionado: {vpnConfigFile.name} · {(vpnConfigFile.size/1024).toFixed(1)} KiB. {connection.protocol==='wireguard'?'O ficheiro será validado e guardado automaticamente ao carregar em Guardar ligação.':'Será validado e guardado ao clicar em Guardar ligação.'}</p>}{connection.provider!=='CyberGhost'&&<label>Ou colar configuração<textarea rows={5} placeholder={connection.protocol==='wireguard'?'[Interface]\nPrivateKey = ...\n\n[Peer]\nPublicKey = ...':'client\ndev tun\nproto udp\nremote ...'} value={vpnConfigText} onChange={e=>{setVpnConfigText(e.target.value);setVpnConfigFile(null)}}/></label>}<small>Os ficheiros de configuração podem conter chaves privadas e certificados. Não serão apresentados após importação.</small></div><label>Identificador técnico (opcional)<input pattern="[a-z][a-z0-9-]{1,31}" placeholder="Gerado a partir do nome" value={connection.id} onChange={e=>setConnection({...connection,id:e.target.value})}/></label><div className="formactions vpn-form-wide"><button className="button" disabled={busy}>Guardar ligação</button></div><p className="muted vpn-form-wide">Depois de guardar o perfil e o ficheiro WireGuard, utiliza Ligar/Desligar na tabela acima. A associação efectiva de hosts à VPN continuará bloqueada até o encaminhamento fail-closed estar validado.</p></form></section></>}
    {page==='policies'&&<><section className="panel"><div className="panelhead"><h2>Políticas por host</h2><span className="softtag">Estado efectivo por host</span></div>{policies.length?<div className="tablewrap"><table><thead><tr><th>Host</th><th>Rota pretendida</th><th>Estado</th><th></th></tr></thead><tbody>{policies.map(p=><tr key={p.id}><td><strong>{p.host_ip}</strong><small>{p.id}</small><small>MAC associado: {p.registered_mac||'Não registado'}</small>{(()=>{const observed=discoveryFinished?neighbors.find(n=>n.ip===p.host_ip):undefined;const mismatch=Boolean(p.registered_mac&&observed&&p.registered_mac.toLowerCase()!==observed.mac.toLowerCase());return <><small>MAC detectado: {observed?.mac||'Não observado'}</small>{mismatch&&<strong style={{color:'#fb7185'}}>● Erro: host diferente</strong>}{p.registered_mac&&!observed&&<small>Identidade não verificável nesta descoberta</small>}{editingIdentity===p.id&&<div><select aria-label={'Corrigir identidade '+p.id} value={draftIdentityMac} onChange={e=>setDraftIdentityMac(e.target.value)}><option value="">Seleccione o dispositivo correcto…</option>{neighbors.filter(n=>n.ip===p.host_ip&&!policies.some(other=>other.id!==p.id&&other.registered_mac?.toLowerCase()===n.mac.toLowerCase())).map(n=><option key={n.ip} value={n.mac}>{n.ip} · {n.mac}</option>)}</select><small>A correcção do IP de uma regra activa exige uma transacção com rollback; não é aplicada automaticamente.</small></div>}</>})()}</td><td><select aria-label={'Rota do host '+p.host_ip} disabled={busy||editingHost!==p.id} value={editingHost===p.id?draftHostRoute:p.destination} onChange={e=>setDraftHostRoute(e.target.value)}><option value="direct">DIRECT</option><option value="blocked">DESABILITADO</option>{connections.map(c=><option key={c.id} value={c.id}>{c.name} ({c.protocol.toUpperCase()})</option>)}</select></td><td>{(()=>{const observed=discoveryFinished?neighbors.find(n=>n.ip===p.host_ip):undefined;const unauthorized=Boolean(p.registered_mac&&observed&&p.registered_mac.toLowerCase()!==observed.mac.toLowerCase());return <span className={"status "+(unauthorized?"error":policyRuntime[p.id]?.status==="active"?"active":"pending")}>{unauthorized?"Erro — Host não autorizado":policyRuntime[p.id]?.status==="active"?"Activo":policyRuntime[p.id]?.status==="pending"?"A aguardar confirmação":policyRuntime[p.id]?.status==="reverted"?"Revertido":policyRuntime[p.id]?.status==="error"?"Erro":"Rascunho"}</span>})()}</td><td>{p.status==='draft'&&p.destination!=='direct'&&p.destination!=='blocked'&&<button type="button" className="textbutton" disabled={busy||identityBusy} onClick={()=>void activateRestoredHost(p.id,p.destination)}>{language==='pt'?'Activar host':'Activate host'}</button>}{editingIdentity===p.id?<>
<button type="button" className="textbutton" disabled={identityBusy||busy||(!draftIdentityMac&&!p.registered_mac)} onClick={async()=>{
 const mac=draftIdentityMac||p.registered_mac||'';
 if(!mac)return;
 if(mac!==p.registered_mac){await saveHostIdentity(p.id,mac);}
 if(draftHostRoute!==p.destination){if(!await changeHostRoute(p.id,draftHostRoute))return;}
 setEditingIdentity(null);setEditingHost(null);
}}>Aplicar</button>
<button type="button" className="textbutton" disabled={identityBusy||busy} onClick={()=>{setEditingIdentity(null);setEditingHost(null);}}>Cancelar</button></>:<button type="button" className="textbutton" disabled={!discoveryFinished||identityBusy||busy} onClick={()=>{
setEditingIdentity(p.id);setDraftIdentityMac(p.registered_mac||neighbors.find(n=>n.ip===p.host_ip)?.mac||'');
setEditingHost(p.id);setDraftHostRoute(p.destination);
}}>Editar</button>}{<button type="button" className="textbutton" disabled={busy||identityBusy} title="Remove a política e as regras; o host pode voltar à rota predefinida" onClick={()=>void removeHostPolicy(p)}>Remover host</button>}{p.vpn_pending&&<button type="button" className="textbutton" disabled={busy} onClick={async()=>{setBusy(true);try{await request('/v1/policies/'+encodeURIComponent(p.id)+'/confirm-vpn',{method:'POST'});await refresh();setMessage('VPN confirmada para '+p.host_ip+'. Reversão automática cancelada.');}catch(e){setMessage(String(e));}finally{setBusy(false);}}}>Confirmar VPN</button>}</td></tr>)}</tbody></table></div>:<div className="empty">Nenhuma política definida. Hosts sem política não serão automaticamente incluídos numa VPN.</div>}</section><section className="panel"><div className="panelhead"><h2>Adicionar regra de host</h2></div><form className="formgrid host-create-form" onSubmit={e=>{e.preventDefault();void save('/v1/policies',{...policy,registered_mac:manualHost?null:(neighbors.find(n=>n.ip===policy.host_ip)?.mac||null),failure_mode:'block'});}}><label>Identificador<input required pattern="[a-z][a-z0-9-]{1,31}" placeholder="host-sala" value={policy.id} onChange={e=>setPolicy({...policy,id:e.target.value.toLowerCase().replace(/[^a-z0-9-]/g,'-')})}/></label><label>Dispositivo identificado na rede<select disabled={!discoveryFinished} required={!manualHost} value={manualHost?'__manual__':policy.host_ip} onChange={e=>{const v=e.target.value;setManualHost(v==='__manual__');setPolicy({...policy,host_ip:v==='__manual__'?'':v});}}><option value="">{refreshingNeighbors?"Em descoberta…":discoveryError?"Descoberta indisponível":"Seleccione um dispositivo"}</option>{neighbors.map(n=><option key={n.ip} value={n.ip} disabled={n.has_policy}>{n.name ? n.name+' · ' : ''}{n.ip} · {n.mac} · {n.state.join('/').toLowerCase()}{n.has_policy?' — política existente':''}</option>)}<option value="__manual__">Introduzir IP manualmente…</option></select>{manualHost&&<input required placeholder="IPv4 do host" value={policy.host_ip} onChange={e=>setPolicy({...policy,host_ip:e.target.value})}/>}<small>Vizinhos observados na LAN; o estado é da cache, não um teste de conectividade. Nomes só aparecem quando confirmados.</small><small>{refreshingNeighbors?"Em descoberta…":discoveryError||"Pesquisa concluída. Os resultados não são alterados durante esta sessão."}</small></label><label>Saída<select value={policy.destination} onChange={e=>setPolicy({...policy,destination:e.target.value})}><option value="direct">DIRECT (sem VPN)</option><option value="blocked">BLOQUEADO (sem Internet)</option>{connections.map(c=><option key={c.id} value={c.id}>{c.name} ({c.protocol})</option>)}</select></label><div className="formactions"><button className="button" disabled={busy}>+ Guardar política</button></div></form></section></>}
    {page==='monitoring'&&<section className="panel"><div className="panelhead"><h2>Monitorização</h2><span className="softtag">Medição real · actualização 5 s</span></div><p className="muted">Tráfego encaminhado dos hosts geridos. Exclui tráfego próprio do gateway.</p>{monitorSamples.length>1&&<div className="traffic-graph"><h3>Velocidade encaminhada · últimas {monitorSamples.length*5} s</h3><svg className="traffic-chart" viewBox="0 0 600 152" preserveAspectRatio="none" role="img" aria-label="Histórico de velocidades dos hosts"><polyline points={monitorSamples.map((p,i)=>{const max=Math.max(1,...monitorSamples.map(x=>Math.max(x.download,x.upload)));return (i*600/Math.max(1,monitorSamples.length-1))+','+(132-p.download*119/max)}).join(' ')} stroke="#17db83" strokeWidth="2.5" fill="none"/><polyline points={monitorSamples.map((p,i)=>{const max=Math.max(1,...monitorSamples.map(x=>Math.max(x.download,x.upload)));return (i*600/Math.max(1,monitorSamples.length-1))+','+(132-p.upload*119/max)}).join(' ')} stroke="#309df3" strokeWidth="2.5" fill="none"/></svg><p>Download (verde) · Upload (azul) · amostras locais da sessão</p></div>}<div className="tablewrap"><table><thead><tr><th>Host</th><th>Rota</th><th>Download</th><th>Upload</th><th>Vel. download</th><th>Vel. upload</th></tr></thead><tbody>{monitorRows.map(h=><tr key={h.ip}><td>{h.ip}</td><td>{h.route}</td><td>{h.rx_bytes==null?'—':(h.rx_bytes/1048576).toFixed(2)+' MB'}</td><td>{h.tx_bytes==null?'—':(h.tx_bytes/1048576).toFixed(2)+' MB'}</td><td>{h.rx_bps==null?'—':(h.rx_bps/1000000).toFixed(3)+' Mbps'}</td><td>{h.tx_bps==null?'—':(h.tx_bps/1000000).toFixed(3)+' Mbps'}</td></tr>)}{!monitorRows.length&&<tr><td colSpan={6}>Sem medições disponíveis.</td></tr>}</tbody></table></div>{moduleError&&<p>{moduleError}</p>}</section>}
    {page==='logs'&&<section className="panel"><div className="panelhead"><h2>Registos</h2><span className="softtag">Últimos 100 eventos VPN</span></div><label>Filtrar eventos <input aria-label="Filtrar registos" placeholder="Perfil, evento ou texto" value={logFilter} onChange={e=>setLogFilter(e.target.value)}/></label><div className="tablewrap"><table><thead><tr><th>Data</th><th>Perfil</th><th>Evento</th><th>Detalhes</th></tr></thead><tbody>{eventRows.filter(e=>(e.profile+' '+e.event+' '+e.detail).toLowerCase().includes(logFilter.toLowerCase())).map((e,i)=><tr key={i}><td>{new Date(e.at).toLocaleString('pt-PT')}</td><td>{e.profile}</td><td>{e.event}</td><td>{e.detail}</td></tr>)}{!eventRows.length&&<tr><td colSpan={4}>Sem eventos registados.</td></tr>}</tbody></table></div>{moduleError&&<p>{moduleError}</p>}</section>}
    {page==='system'&&<><section className="panel system-panel"><div className="panelhead"><h2>{t.system}</h2><span className="softtag">{t.status}</span></div>

    <div className="check">WebAdmin: <strong>{healthSummary?.webadmin||t.checking}</strong></div>
    <div className="check">{t.database}: <strong>{healthSummary?.database||t.checking}</strong></div>
    <div className="check">{t.profiles}: <strong>{healthSummary?.profiles??'—'}</strong></div>
    <div className="check">{t.hosts}: <strong>{healthSummary?.policies??'—'}</strong></div>
    <div className="check">{t.dns}: <strong>{healthSummary?.services?.pihole_dns?t.operational:t.unverified}</strong></div>
    <div className="check">{t.connected}: <strong>{healthSummary?.services?.vpn_connected??'—'}</strong></div>
    <div className="check">{t.storage}: <strong>{healthSummary?.disk_total_bytes?((healthSummary.disk_used_bytes/healthSummary.disk_total_bytes)*100).toFixed(1)+'%':'—'}</strong></div>
    {moduleError&&<p role="alert">{moduleError}</p>}</section>
    <section className="panel system-panel"><div className="panelhead"><h2>{t.backup}</h2></div><p className="muted">{t.notice}</p>
    <div className="system-backup-form"><label>{t.password}<input type="password" autoComplete="new-password" minLength={12} maxLength={256} aria-describedby="backup-password-help" value={backupPassword} onChange={e=>setBackupPassword(e.target.value)}/><small id="backup-password-help" className={backupPassword.length>=12?"password-valid":"password-hint"}>{language==='pt'?(backupPassword.length>=12?'Palavra-passe válida':`Mínimo 12 caracteres (${backupPassword.length}/12)`):(backupPassword.length>=12?'Password valid':`Minimum 12 characters (${backupPassword.length}/12)`)}</small></label><div className="system-actions"><button className="button" type="button" disabled={maintenanceBusy||backupPassword.length<12} onClick={()=>void downloadBackup()}>{t.download}</button></div></div></section>
    <section className="panel system-panel"><div className="panelhead"><h2>{t.restore}</h2></div>
    <div className="system-form"><label>{t.choose}<input aria-label={t.choose} type="file" accept=".json,application/json" onChange={e=>{setRestoreFile(e.target.files?.[0]||null);setRestorePreflight(null);setRestoreError('');setInterfaceMapping({});}}/></label>
    <label>{t.restorePassword}<input type="password" autoComplete="off" value={restorePassword} onChange={e=>{setRestorePassword(e.target.value);setRestorePreflight(null);setRestoreError('');}}/></label>
    <button className="button" type="button" disabled={maintenanceBusy||!restoreFile||restorePassword.length<12} onClick={()=>void checkRestore()}>{language==='pt'?'Verificar compatibilidade do servidor':'Check server compatibility'}</button>
    {restorePreflight&&<div role="status"><p><strong>{restorePreflight.compatible?(language==='pt'?'Compatível':'Compatible'):(language==='pt'?'Incompatível — restauro bloqueado':'Incompatible — restore blocked')}</strong> · VPNs: {restorePreflight.vpn_count} · Hosts: {restorePreflight.host_count}</p>{Object.entries(restorePreflight.options||{}).map(([source,targets])=><label key={source}>{source} → {language==='pt'?'Interface de destino':'Destination interface'}<select value={interfaceMapping[source]||''} onChange={e=>{setInterfaceMapping(old=>({...old,[source]:e.target.value}));setRestorePreflight(old=>old?{...old,compatible:false}:null);}}><option value="">{language==='pt'?'Seleccionar':'Select'}</option>{targets.map(dest=><option key={dest} value={dest}>{dest}</option>)}</select></label>)}{restorePreflight.issues.map((issue,index)=><p key={index} role="alert">⚠ {issue}</p>)}{!restorePreflight.compatible&&<button type="button" className="button" disabled={maintenanceBusy} onClick={()=>void checkRestore()}>{language==='pt'?'Revalidar correspondências':'Revalidate mappings'}</button>}</div>}
    {restoreError&&<p role="alert" className="restore-error">{restoreError}</p>}
    <label>{t.confirmRestore}<input aria-label={t.confirmRestore} placeholder="RESTORE" value={restoreConfirm} onChange={e=>setRestoreConfirm(e.target.value)}/></label>
    <div className="system-actions"><button className="button" type="button" disabled={maintenanceBusy||!restoreFile||restorePassword.length<12||restoreConfirm!=='RESTORE'||!restorePreflight?.compatible} onClick={()=>void applyMaintenance('restore')}>{t.restoreButton}</button></div></div></section>
    <section className="panel system-panel"><div className="panelhead"><h2>{t.defaults}</h2></div><p className="muted">{t.warning}</p>
    <div className="system-form"><label>{t.confirmReset}<input aria-label={t.confirmReset} placeholder="RESET" value={resetConfirm} onChange={e=>setResetConfirm(e.target.value)}/></label>
    <div className="system-actions"><button className="button danger" type="button" disabled={maintenanceBusy||resetConfirm!=='RESET'} onClick={()=>void applyMaintenance('defaults')}>{t.resetButton}</button></div></div></section></>}
    {page==='diagnostics'&&<><section className="panel"><div className="panelhead"><h2>Diagnóstico do Gateway VPN Multi</h2><span className="softtag">Ambiente actual · leitura em tempo real</span></div><p className="muted">Diagnóstico dos túneis e das políticas de host actualmente geridos no gateway. Para testar perdas de ligação, DNS e IPv6 nos clientes, consulte os testes de aceitação executados directamente nos equipamentos.</p><div className="cards three"><div className="stat"><span>Perfis VPN</span><b>{connections.length}</b><small>Perfis configurados</small></div><div className="stat"><span>Túneis WireGuard ligados</span><b>{wgStatuses.filter(v=>v.connected).length}</b><small>Handshake recente confirmado</small></div><div className="stat"><span>Políticas de hosts</span><b>{policies.length}</b><small>Associações configuradas</small></div></div></section><section className="panel"><div className="panelhead"><h2>Estado dos túneis</h2><span className="softtag">Verificação real</span></div><div className="tablewrap"><table><thead><tr><th>VPN</th><th>Interface</th><th>Estado</th><th>IP público verificado</th></tr></thead><tbody>{connections.map(c=>{const v=wgStatuses.find(w=>w.id===c.id);return <tr key={c.id}><td>{c.name}</td><td>{v?.interface_name||'—'}</td><td>{v?.connected?'Ligado':v?.tunnel_active?'A aguardar handshake':'Desligado / não verificado'}</td><td>{v?.public_ipv4||'Não verificado'}</td></tr>})}</tbody></table></div></section><section className="panel"><div className="panelhead"><h2>Políticas e identidades</h2><span className="softtag">Hosts configurados</span></div><div className="panelhead"><h2>Verificação efectiva no gateway</h2><span className="softtag">Kernel · 10 s</span></div><div className="tablewrap"><table><thead><tr><th>Host</th><th>Rota efectiva</th><th>Firewall</th><th>Kill switch</th><th>Identidade MAC</th><th>DNS / IPv6</th></tr></thead><tbody>{diagnosticRows.map(h=><tr key={h.ip}><td>{h.ip}</td><td title={h.observed_route||''}>{h.route_verified?'Verificada':'Falha / não verificada'}</td><td>{h.firewall_verified?'Verificada':'Falha'}</td><td>{h.vpn_guard_present===null?'Não aplicável':h.vpn_guard_present?'Protecção presente':'Falha'}</td><td>{h.identity==='authorized'?'Autorizado':h.identity==='unauthorized'?'MAC diferente':'Não verificável'} · {h.observed_mac||'Sem observação'}</td><td>DNS: regras configuradas, fuga não comprovada; IPv6: não suportado / bloqueado</td></tr>)}{!diagnosticRows.length&&<tr><td colSpan={6}>Sem resultados da verificação.</td></tr>}</tbody></table></div>{diagnosticError&&<p className="muted">{diagnosticError}</p>}
<div className="tablewrap"><table><thead><tr><th>IP</th><th>Destino</th><th>MAC associado</th><th>Estado da política</th></tr></thead><tbody>{policies.map(p=><tr key={p.id}><td>{p.host_ip}</td><td>{p.destination}</td><td>{p.registered_mac||'Não definido'}</td><td>{p.status}{p.vpn_pending?' · aguarda confirmação':''}</td></tr>)}</tbody></table></div><p className="muted">Uma política activa não certifica, por si só, ausência de fugas. A verificação de rota efectiva, MAC observado e tráfego deve ser efectuada com os testes reais dos clientes.</p></section><section className="panel"><div className="panelhead"><h2>Capacidades do servidor</h2><span className="softtag">Consulta sem alterações</span></div>{runtime?<><div className="check">WireGuard: {runtime.tools.wireguard?'Instalado':'Indisponível'} · OpenVPN: {runtime.tools.openvpn?'Instalado':'Indisponível'}</div><div className="check">iproute2: {runtime.tools.iproute2?'Disponível':'Indisponível'} · nftables: {runtime.tools.nftables?'Disponível':'Indisponível'}</div><div className="check">Dispositivo TUN: {runtime.tun_device?'Disponível':'Indisponível'}</div></>:<p className="muted">A carregar capacidades…</p>}</section></>}
</div>
  </div>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);

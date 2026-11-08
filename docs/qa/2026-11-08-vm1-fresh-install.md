# QA VM1 — Fresh Install Ubuntu 22.04.5 (2026-11-08)

## Origem e ambiente

- Projecto: Gateway VPN Multi, versão `1.0.6-rc.1`.
- Origem pública: `https://github.com/emmanique/vpngateway-webadmin`.
- Revisão exacta instalada: `8b3bf6324e0c99ebec38212b73632bae9656e1fe` (checkout detached).
- VM nova: hostname `gateway`, Ubuntu 22.04.5 LTS KVM, interface `ens18`, IP de gestão `192.168.1.235/24`, router predefinido `192.168.1.1`.
- Recursos: 4 GiB RAM, 2 GiB swap, 15 GB de disco virtual; cerca de 4.2 GB livres após instalação.

## Incidente detectado e corrigido

A primeira execução de `sudo bash start.sh --lan-interface ens18 --lan-ip 192.168.1.235` instalou os pacotes APT, mas terminou no preflight de dependências, porque shells root não-interactivas não tinham `/usr/sbin` no PATH. Os binários `nft` e `openvpn` estavam correctamente instalados em `/usr/sbin`, mas `command -v` falhava.

Correcção publicada: `fc0a6cc0148fdcaea96a4793dc56661013b85eb9` normaliza o PATH antes das verificações. Teste de regressão: `8b3bf6324e0c99ebec38212b73632bae9656e1fe`. Reexecução do preflight com PATH limitado: PASS. Seis testes contratuais do instalador: PASS.

## Segunda execução — PASS

- Instalador terminou `INSTALL_EXIT=0`.
- Imagens WebAdmin e VPN construídas a partir da revisão pública: `vpngateway/webadmin:1.0.6-rc.1` e `vpngateway/vpn:1.0.6-rc.1`.
- Quatro contentores iniciados: WebAdmin, VPN, Pi-hole e Nginx HTTPS.
- Gestão HTTPS `https://192.168.1.235/`: HTTP 200, TLS verificado com certificado local.
- Administração Pi-hole `https://192.168.1.235:8443/`: HTTP 302 (redireccionamento esperado), TLS verificado.
- Certificado inicial apresenta SAN `IP Address:192.168.1.235`.
- Ficheiros `deploy/.env` e `deploy/tls-local/lan.key` com permissões 0600.
- Docker, `vpngw-policy-agent.service`, `vpngw-pihole-dns-acl.service` e `vpngw-discovery.timer`: activos e habilitados.
- Pi-hole `healthy`, FTL a escutar DNS TCP/UDP.
- Consulta DNS UDP directa a `192.168.1.235:53`: RCODE 0, 1 resposta.
- ACL `inet vpngw_pihole_dns` presente.
- Reboot do sistema: PASS, os serviços/container regressaram e HTTPS/DNS mantiveram funcionamento; kernel activo `5.15.0-203-generic`.
- `./start.sh --check --lan-interface ens18 --lan-ip 192.168.1.235` depois de reboot: PASS.
- Sem unidades systemd em estado `failed` durante a recolha.

## Evidências e limitações

- Log de instalação local: `/var/tmp/vpngw-fresh-install-qa.log`.
- Arquivo de evidências local: `/var/tmp/fresh-install-qa/gateway-20261108T152045Z.tar.gz`; analisar endereços antes de partilhar.
- Não foram copiados secrets, chaves ou volumes dos antigos servidores.
- Não há ainda VPN WireGuard/OpenVPN configurada, políticas de hosts, ligação de cliente via Gateway, teste de kill-switch, NAT-PMP, porta acessível externamente ou recuperação de falhas do túnel.
- A configuração da topologia e a activação funcional na interface WebAdmin são gates separados.
- O armazenamento livre é suficiente para a instalação observada, mas a capacidade deve ser aumentada para retenção prolongada de logs, imagens e futuras actualizações.

**Decisão QA VM1:** Fresh install, reboot, WebAdmin HTTPS, DNS e persistência básica: **PASS**. Funcionalidade VPN/rotas/NAT/recuperação: **PENDENTE**, logo **NO-GO para aceitação integral de Gateway**.

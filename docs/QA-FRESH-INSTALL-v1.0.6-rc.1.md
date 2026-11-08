# VPN Gateway 1.0.6-rc.1 — preparação para instalação limpa

**Fonte pública congelada para esta QA:** commit 4faeda2ce5a16dd3e21563fbbca9f09f25ceb2a8 (branch main no momento da compilação).

## Alterações posteriores à release v1.0.5

- Bootstrap MediaHub corrige a separação entre o endereço IP de gestão do VPN Gateway e o router por defeito do Stremio.
- Instalador Linux aceita Docker Compose v2 com nomes de pacotes Debian 13, Ubuntu e Docker upstream.
- Instalador verifica Docker Buildx e instala o plugin em falta por APT.
- Primeira instalação gera uma password Pi-hole aleatória (24 bytes) e persiste-a em deploy/.env com permissões 0600; instalações anteriores não são sobrescritas.
- Contratos de instalação actualizados para não perpetuar o modo sem password por defeito.

## Evidência local isolada — 2026-11-08

- Clone público e bash -n do instalador: PASS.
- Auditoria de 116 ficheiros, nenhuma dependência literal de IP/host legado: PASS.
- Testes específicos do instalador: 4 PASS.
- Testes Python em Python 3.12, num contentor descartável com dependências de apps/api/requirements.txt: **359 PASS**.
- Construção de arquivos tar.gz e ZIP a partir de git HEAD: PASS.
- Manifesto e SHA-256 dos dois arquivos: PASS.

## Actualização do contrato de imagens e nova regressão

A revisão 1178cbb31c1d9ecd7d362f178f87f81ed53b7806 actualiza o Docker Compose para gerar as tags a partir de VERSION (1.0.6-rc.1) e não das tags históricas 1.0.3. O Compose resolvido com os overlays de gestão, descoberta, política e Pi-hole confirmou ambas as imagens locais versionadas. A suite Python 3.12 foi reexecutada com **360 testes aprovados** e a imagem Pi-hole fixada por digest foi verificada no registry.

Esta é a revisão de código recomendada para a QA de fresh install. O documento e os arquivos de distribuição poderão ter SHA posterior por conterem provas e manifests, mas o código aplicacional validado corresponde à revisão acima.

## Pacotes QA produzidos localmente

- gateway-vpn-multi-1.0.6-rc.1-deployment.tar.gz — sha256 a4702da55fc4f55efc1a397023a42bdf7688e535fd9315442bba7ee568f29053
- gateway-vpn-multi-1.0.6-rc.1-deployment.zip — sha256 7a7fe6911df151775da85d570200509ec339f7405d2b569a3b81dec019640ac8

Os hashes acima pertencem ao snapshot anterior 4faeda2 (antes da correcção das tags das imagens) e não devem ser usados como pacotes finais. Esses arquivos foram compilados e verificados num host QA, mas **ainda não foram anexados a um GitHub Release ou tag formal**. Para testar de forma reproduzível num terceiro servidor sem os pacotes, clonar a origem pública e fazer checkout do commit acima, depois executar sudo ./start.sh com a interface e o IP LAN reais. Não usar uma release 1.0.5 para validar o bootstrap actualizado.

## Limites do certificado QA

- Uma execução sudo ./start.sh completa num Debian/Ubuntu limpo, com reboot, ainda requer as novas máquinas.
- Build do frontend React e imagens Docker exactas, WireGuard/OpenVPN reais, Direct/VPN/Bloqueado, DHCP/MAC, DNS fail-closed e NAT-PMP externo precisam de QA funcional.
- A API read-only 9443 e o observador Stremio são opt-in; instalar e activar só depois de validar CA, token e policy ID.
- Nenhuma alteração no Gateway de produção ou no Stremio de produção foi executada por este ensaio.

**Decisão:** pronto para ensaio de fresh install controlado, NÃO aprovado para GA/produção.

## Verificação de reproducibilidade e QA operacional adicional

Em 2026-11-08 a rotina scripts/build-release-packages.py foi corrigida para gravar metadados gzip determinísticos (mtime=0, sem filename embutido). **Duas compilações sucessivas da mesma revisão 4ea8760846e316cdd090077d5661a9a8334bcab2 produziram hashes idênticos:**

- tar.gz: e1ed361a610b9367454374c761a4bfe485cf4157065e936fdc7a8a6ec62d7663
- zip: 1fc6161e01e75a81281255ed7e80f4f67124d54ad289260dfd9616e915e6e8c6

Este teste é uma prova de build reprodutível no mesmo ambiente, não uma release GitHub publicada. O manifesto gerado no host QA deve ser preservado com a revisão de código exacta. A última distribuição oficial anterior continua v1.0.5. O desenvolvimento QA é mantido em main como 1.0.6-rc.1 até ser disponibilizada uma tag/release e serem aprovados os testes nas máquinas novas.

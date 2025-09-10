# Descrição Detalhada - SCCMReinstall.ps1

O **SCCMReinstall.ps1** é um script em PowerShell desenvolvido para auxiliar administradores de sistemas na reinstalação do cliente **SCCM/MECM (System Center Configuration Manager / Microsoft Endpoint Configuration Manager)** em máquinas Windows.

## Funcionalidades principais
- Remove instalações antigas do agente SCCM (limpeza de registros e serviços).
- Faz download do pacote de instalação a partir de um ZIP previamente definido.
- Extrai o conteúdo e localiza o executável `ccmsetup.exe`.
- Executa a instalação com parâmetros configuráveis (Management Point, Site Code, etc.).
- Gera logs detalhados de todo o processo em arquivo (`SCCMClientInstall.log`).
- Previne que o sistema entre em suspensão durante a execução.
- Valida a instalação final verificando serviços e componentes críticos.

## Benefícios
- Reduz tempo de troubleshooting em ambientes corporativos.
- Facilita automação em massa (pode ser usado em GPO, Intune ou orquestradores).

## Pré-requisitos
- Executar como Administrador.
- Garantir conectividade com o servidor SCCM/Management Point.
- Ter o pacote de instalação válido do SCCM acessível no caminho configurado.

---
**Autor:** Alan Kordel  
**Data de criação:** 2025-09-10  

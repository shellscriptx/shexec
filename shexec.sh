#!/bin/bash

#-----------------------------------------------------------------------------------------------
# Data: 27 de agosto de 2016
# Criado por: Juliano Santos [x_SHAMAN_x]
# Script: shexec
# Descrição: Script para execução de comando(s), scripts(s) ou projeto(s) em
#			 computadores em massa na rede. Foi desenvolvido com uma GUI utilizando
#			 o 'yad', possue recursos via linha comando. '<script> --help' para obter
#			 mais informações. Usando recursos de tunnel ssh com modos de autenticação
#			 tanto por usuario/senha como Chave Pública. As tarefas pode ser salvas
#			 em um arquivo de Perfil (*.shexec), que posteriormente poderá ser carregado
#			 pelo script.
#
#			 Opção - Execução:
#			 Dispôe de 3 modos de execução.
#			 Comando - Conjunto de comandos separados por ';' (ponto-e-virgula)
#			 Script -  Arquivo (Shell Script) composto com uma cadeia de comandos.
#			 Projeto - Pasta contendo os arquivos do projeto ou scripts.
#			 Projeto [Script] - Arquivo (Shell Script) do projeto que será executado primeiro
#
#		     Opção - Computadores
#			 Arq. Host - Arquivo contendo uma lista de Hostname(s)/IP(s)
#			 Lista de Hosts - Usuário poderá inserir uma lista personalizada.
#			 Intervalo de IP - Define um intervalo entre endereços (Inicial e Final).
#							   Exemplo: Inicio: 192.168.0.1 Final: 192.168.0.255 
#										= 255 IPs -> 192.168.0.[1] até [255]
#
#			 Notificação por email com log's em anexo, após o término das execuções.
#			 Usuário também poderá criar agendamentos.
#
#-----------------------------------------------------------------------------------------------

# Checa as dependências.
for pkg in ssh sshpass yad sendemail cron; do
	# Consulta informações do comando e se o retorno for nulo,
	# imprime mensagem de erro e finaliza o script
	if ! command -v $pkg &>/dev/null; then
		echo "shexec: erro: '$pkg' não está instalado." 1>&2; fi
done

export DISPLAY=:0						# Define a identificação do video na chamada de aplicações usando X11 dentro do crontab
export XAUTHORITY=$HOME/.Xauthority		# Seta o arquivo de autoridade do X
declare -r SCRIPT=shexec				# Script
declare -r CONF=$HOME/.shexec.conf		# Configurações avançadas (Email, Conexão, Agendamento)
declare TMP_PROJECT=$(mktemp --tmpdir=/tmp --directory shexec.XXXXXXXXXX)	# Cria o diretório temporário para armazenar o projeto
declare TMP_SCRIPT=$(mktemp --tmpdir=$TMP_PROJECT shexec.XXXXXXXXXX)		# Cria o script temporário para chama em escala

# Configurações padrões de inicialização
declare _PROFILE=''							# Perfil
declare _COMMAND='' 						# Comandos
declare _SCRIPT='' 							# Script
declare _PROJECT=''							# Projeto
declare _P_SCRIPT='' 						# Projeto [Script]
declare _USER='' 							# Usuário
declare _PASS='' 							# Senha
declare _SSH_KEY='' 						# Chave RSA
declare _CHK_ROOT_RUN=FALSE 				# Executar como root
declare _ROOT_PASS='' 						# Senha de root
declare _HOST_FILE=''						# Arquivo de hosts
declare _IP_START=''						# IP Inicial
declare _IP_END=''							# IP Final
declare _CHK_ERR=FALSE 						# Fechar se houver erro
declare _CHK_LOG=FALSE						# Criar LOG
declare _CHK_FAIL=FALSE 					# Criar LOG Malsucedidos
declare _CHK_COMPRESS_LOG=FALSE				# Compactar LOG
declare _CHK_NOTIFICATION=FALSE				# Notificar

declare HOST_LIST=/tmp/hosts.list		# Arquivo temporário para armazenar hosts inseridos em tempo de execução
declare TMP_HOSTS=/tmp/hlist			# Todos os hosts usados pelo usuário


# Limpa o cache se o script for interrompido pelo usuário
trap '_exit' INT
	
# Suprime os erros
exec 2>/dev/null

function _exit()
{
	# Remove todos os arquivos/diretórios temporários gerados pelo script
	rm -f $HOST_LIST /tmp/save.$$ $TMP_HOSTS $TMP_SCRIPT $CRON_LIST $CRON_SYS $CRON_OTHER
	rm -rf $TMP_PROJECT
	
	# Sai com status 0
	exit 0
}
	
function message.error()
{
	# Imprime a mensagem de erro no 'RUNLEVEL' especificado.
	case $RUNLEVEL in
		3) echo -e "Erro: $1"; _exit;;
		7) yad --form --title="Error" --text="$1" --fixed --center --button="OK":0 --image=gtk-dialog-error;;
	esac
	# Desvia o fluxo do script.
	case $2 in
		0) return 0;;
		1) main;;
		2) settings;;
		3) set_schedule;;
	esac
}

function check_ip()
{
	# Inicia o status da verificação
	# 1 - Falso
	local RETVAL=1

	# Verifica se o 'IP' possui um formato válido.
	if [[ "$1" =~ ^[0-9]{,3}[.]{1}[0-9]{,3}[.]{1}[0-9]{,3}[.]{1}[0-9]{,3}$ ]]; then
		IFS='.'		# Delimitador
		ip=($1)		# Separa os octetos
		# Verifica se o valor de cada octeto é inferior a 256	
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        RETVAL=$?	#	Obtem retorno da condição.
	fi

	unset IFS		# Limpa o delimitador
	return $RETVAL	# Retorna status
}

function check_fields()
{
	# Essa função verifica todos os campos inseridos pelo usuário, tratando as opções
	# obrigatórias a opcionais. Campos com valores inválidos, imprime a mensagem de
	# erro e retorna a função padrão
	
	# Se todos os campos de 'Execução' foram omitidos.
	if [ ! "$_COMMAND" -a ! "$_SCRIPT" -a ! "$_PROJECT" -a ! "$_P_SCRIPT" ]; then
		message.error "Não existe comando ou script configurado." 1; fi

	# Se o 'script' for informado, verifica se ele existe.
	if [ "$_SCRIPT" -a ! -e "$_SCRIPT" ]; then
		message.error "Script: '$_SCRIPT' Arquivo não encontrado." 1; fi

	# Se o 'projeto' ou 'Projeto [script]' for especificado, verifica se ambos existem.
	# Quando um dos campos é especificado, ambos se tornam obrigatórios.
	if [ "$_PROJECT" -o "$_P_SCRIPT" ]; then
		if [ ! -e "$_PROJECT" ]; then
			message.error "Projeto: '$_PROJECT' Diretório não encontrado." 1
		elif [ ! -e "$_P_SCRIPT" ]; then
			message.error "Projeto [Script]: '$_P_SCRIPT' Arquivo não encontrado." 1
		fi
	fi

	# Se executar como root for selecionado, checa se o campo 'Senha (root)' está vazio.
	if [[ "$_CHK_ROOT_RUN" == ?(TRUE|true) ]] && [[ ! "$_ROOT_PASS" ]]; then
		message.error "Executar como root: Senha root não pode ser nula." 1; fi
	
	# Se a 'Chave RSA' for especificada, verifica se os campos 'usuario' e 'senha' estão vazios.
	# A autenticação por chave pública não requer usuario/senha.
	if [ "$_SSH_KEY" ]; then
		if [ "$_USER" -o "$_PASS" ]; then
			 message.error "Chave RSA: Uso da 'chave' não requer usuário/senha." 1
		# Testa o fingerprint do arquivo de chave pública espeficiado
		elif ! ssh-keygen -lf $_SSH_KEY &>/dev/null; then
			message.error "Chave RSA: '$_SSH_KEY' Chave RSA pública inválida." 1
		fi
	else
		# Autenticação por usuário/senha.
		# Verifica se ambos os campos estão vazios.
		if [ ! "$_USER" ]; then
			message.error "Usuário: Não pode ser nulo." 1
		elif [ ! "$_PASS" ]; then
			message.error "Senha: Não pode ser nula." 1
		fi
	fi

	# Se o arquivo de 'hosts' for especificado, verifica se ele existe.
	if [ "$_HOST_FILE" ]; then
		if [ -e "$_HOST_FILE" ]; then	
			# Verifica se os 'IPs' contidos no arquivo são válidos.
			for IP in $(egrep -v "^$|[[:alpha:]]" "$_HOST_FILE"); do	
				if ! check_ip $IP; then
					message.error "Arq. Host: '$_HOST_FILE' O conteúdo do arquivo possui endereço(s) de IP inválido(s).\nInválido(s): $IP" 1
				fi
			done
		else
			# Se o arquivo não existir.
			message.error "Arq. Host: '$_HOST_FILE' Arquivo não encontrado." 1
		fi
	fi

	# Se um dos campos 'Intervalo de IPs' for especificado.
	if [  "$_IP_START" -o "$_IP_END" ]; then
			# Verifica o IP
			# 1 - IP Inválido
			# 0 - Válido
			if ! check_ip $_IP_START; then
				message.error "Inicio: '$_IP_START' Endereço de IP inválido." 1; fi
			if ! check_ip $_IP_END; then
				message.error "Fim: '$_IP_END' Endereço de IP inválido." 1; fi
	fi
	
	# Lê a 'Lista de hosts'
	if [ -e "$HOST_LIST" ]; then
		for IP in $(egrep -v "^$|[[:alpha:]]" "$HOST_LIST"); do
			# Validação do IP
			if ! check_ip $IP; then
				message.error "Lista de Hosts: O conteúdo da lista possui endereços de IP(s) inválido(s).\nInválido(S): $IP" 1
			fi
		done
	fi
	
	# Cria um arquivo temporário 'TMP_HOSTS' e armazena os 'hosts' contidos em 'HOST_LIST' e '_HOST_FILE'
	cat $HOST_LIST $_HOST_FILE | tr ' ' '\n' | egrep -v "^$|^[[:blank:]]*#" > $TMP_HOSTS
		
	# 'Intervalo de IPs'
	# Se ambos os campos forem especificados
	if [ "$_IP_START" -a "$_IP_END" ]; then
		# Delimitador
		IFS='.'		
		ip_s=($_IP_START)	# Separa os octetos do ip inicial
		ip_e=($_IP_END)		# Separa os octetos do ip final
		# Inicia a enumeração dos intervalos de cada octeto e grava no arquivo 'TMP_HOSTS'. ip_s até ip_e.
		eval printf "%s\\\n" {${ip_s[0]}..${ip_e[0]}}.{${ip_s[1]}..${ip_e[1]}}.{${ip_s[2]}..${ip_e[2]}}.{${ip_s[3]}..${ip_e[3]}} >> $TMP_HOSTS
		unset IFS	# limpa o delimitador
	fi

	# Obtem a quantidade de hosts duplicados.
	local dup="$(sort $TMP_HOSTS | uniq -D)"
	
	# Verifica se a lista de hosts está vazia.
	if [ $(cat $TMP_HOSTS | wc -l) -eq 0 ]; then
		message.error "Hosts: Não foi encontrado um 'Hostname/IP' cadastrado." 1
	# Se 'dup (duplicados)' não for nulo, imprime mensagem de erro e quantidade de itens duplicados.
	elif [ "$dup"  ]; then
		message.error "Hosts: Foi encontrado conflitos de 'Hostnames/IPs'.\nConflitos:\n$dup" 1
	fi
	
}
function win_hosts()
{
	# Janela 'Lista de Hosts'
    # Tenta ler o arquivo de hosts
    for line in $(cat $HOST_LIST 2>/dev/null); do
        echo "$line" 
    # Rediciona a saida para lista e avalia o status de retorno da janela.
    # Salvar:0 - Salva a lista em um arquivo temporário e renomeia para um arquivo 'HOST_LIST' válido
    done | if yad --title="Hosts" \
                    --text="Crie uma lista de hosts personalizada.\nVocê poderá cadastrar os computadores\npelo <b>'IP'</b> ou <b>'Hostname'</b>." \
                    --center \
                    --fixed \
                    --separator='' \
                    --width=300 \
                    --height=600 \
                    --button='Salvar!gtk-save!Salva os dados da lista':0 \
                    --button='Cancelar!gtk-cancel!Sai sem salvar alterações':1 \
                    --print-all \
                    --list \
                    --editable --column="Nome/IP" > /tmp/save.$$; then
                    mv /tmp/save.$$ $HOST_LIST; fi

    # Encerra o subshell
    exit 0
}

function load_profile()
{
	# Perfil
	_profile="$1"
	
	# Se 'profile' existir, lê o valor das variáveis do perfil
	if [ -e "$_profile" ]; then
		_PROFILE="$_profile"																						# dir/arquivo de perfil
		_COMMAND="$(egrep -m1 "^[[:blank:]]*COMMAND" "$_profile" | cut -d'=' -f2-)"									# Linha de comando
		_SCRIPT="$(egrep -m1 "^[[:blank:]]*SCRIPT" "$_profile" | cut -d'=' -f2-)"									# Script
   		_PROJECT="$(egrep -m1 "^[[:blank:]]*PROJECT" "$_profile" | cut -d'=' -f2-)"									# Projeto
		_P_SCRIPT="$(egrep -m1 "^[[:blank:]]*INIT_SCRIPT" "$_profile" | cut -d'=' -f2-)"							# Projeto [Script]
	   	_USER="$(egrep -m1 "^[[:blank:]]*USERNAME" "$_profile" | cut -d'=' -f2-)"									# Usuário
	   	_PASS="$(egrep -m1 "^[[:blank:]]*PASSWORD" "$_profile" | cut -d'=' -f2-)"									# Senha
	   	_SSH_KEY="$(egrep -m1 "^[[:blank:]]*SSH_KEY" "$_profile" | cut -d'=' -f2-)"									# Chave RSA
	   	_CHK_ROOT_RUN="$(egrep -m1 "^[[:blank:]]*ROOT_RUN" "$_profile" | cut -d'=' -f2-)"							# Executar como root
	   	_ROOT_PASS="$(egrep -m1 "^[[:blank:]]*ROOT_PASSWORD" "$_profile" | cut -d'=' -f2-)"							# Senha do root
	   	_HOST_FILE="$(egrep -m1 "^[[:blank:]]*HOST_FILE" "$_profile" | cut -d'=' -f2-)"								# Arquivo de hosts
		_IP_START="$(egrep -m1 "^[[:blank:]]*IP_START" "$_profile" | cut -d'=' -f2-)"								# IP Inicial
	   	_IP_END="$(egrep -m1 "^[[:blank:]]*IP_END" "$_profile" | cut -d'=' -f2-)"									# IP Final
	   	_CHK_ERR="$(egrep -m1 "^[[:blank:]]*EXIT_ERR" "$_profile" | cut -d'=' -f2-)"								# Debug erro
	   	_CHK_LOG="$(egrep -m1 "^[[:blank:]]*LOG" "$_profile" | cut -d'=' -f2-)"										# Gerar LOG
	   	_CHK_FAIL="$(egrep -m1 "^[[:blank:]]*FAIL" "$_profile" | cut -d'=' -f2-)"									# Gerar LOG Malsucedidos
	   	_CHK_COMPRESS_LOG="$(egrep -m1 "^[[:blank:]]*COMPRESS_LOG" "$_profile" | cut -d'=' -f2-)"					# Compactar LOG
	   	_CHK_NOTIFICATION="$(egrep -m1 "^[[:blank:]]*NOTIFICATION" "$_profile" | cut -d'=' -f2-)"					# Notificar
	   	echo $(egrep -m1 "^[[:blank:]]*HOST_LIST" "$_profile" | cut -d'=' -f2-) | tr ' ' '\n'  > $HOST_LIST			# Lista de hosts
	else
		# Se o arquivo não existir.
		message.error "Perfil: '$_profile' Arquivo não encontrado." 1
	fi
}

function profile()
{
	local _profile
    # Lẽ o parâmetro e execução função
    case $1 in
        new)
            # Limpa todos os campos enviando um caractere nulo aos seus respectivos identificadores.
			printf "3:\n4:\n5:\n6:\n13:\n14:\n15:\n16:\n17:\n23:\n26:\n27:\n29:\n33:\n34:\n35:\n36:\n37:\n"
            rm -f $HOST_LIST    # Remove lista personalizada.
            ;;
        load)
            # Exibe a janela para selecionar o arquivo de perfil.
            if _profile=$(yad --title="Carregar perfil..." \
                            --center \
                            --width=600 \
                            --height=500 \
                            --fixed \
                            --file --file-filter="Perfil (*.shexec)|*.shexec" \
                            --add-preview); then
				# OK: 0 -> Lê o perfil e inicializa as variaveis
				load_profile $_profile

				# Lê os valores da variaveis e rediciona para os identificadores dos campos.
				printf "3:%s\n4:%s\n5:%s\n6:%s\n13:%s\n14:%s\n15:%s\n16:%s\n17:%s\n23:%s\n26:%s\n27:%s\n29:%s\n33:%s\n34:%s\n35:%s\n36:%s\n37:%s\n" \
				"$_COMMAND" "$_SCRIPT" "$_PROJECT" "$_P_SCRIPT" "$_USER" "$_PASS" "$_SSH_KEY" "$_CHK_ROOT_RUN" "$ROOT_PASS" "$_HOST_FILE" "$_IP_START" "$_IP_END" "$_PROFILE" "$_CHK_ERR" "$_CHK_LOG" "$_CHK_FAIL" "$_CHK_COMPRESS_LOG" "$_CHK_NOTIFICATION"
            fi
            ;;
        save)
            # Armazena em 'VAL' todos paramêtros da função e atualiza os valores separados delimitador '|'
			VAL="${*:2}"; IFS='|'; VAL=($VAL)
		
			# Arquivo de perfil
            _profile=${VAL[12]}
           
			# Se 'perfil' não existir, exibe a janela 'Salvar'
            if [ ! "$_profile" ]; then
                _profile=$(yad --title="Salvar perfil..." \
                            --center \
                            --width=600 \
                            --height=500 \
                            --file \
                            --filename="perfil.shexec" \
                            --save \
                            --confirm-overwrite="Deseja substituir o arquivo ?" \
                            --file-filter="Perfil (.shexec)|*.shexec" \
                            --add-preview)
			fi
			
			# Grava as configurações do perfil
            cat > "$_profile" << EOF
# Script: $SCRIPT
# Perfil: $(basename "$_profile")
# Arquivo de perfil gerado automaticamente com configurações personalizadas de execução.
# Utilize as variáveis para inserir dados manualmente.

# Execução
COMMAND=${VAL[0]}
SCRIPT=${VAL[1]}
PROJECT=${VAL[2]}
INIT_SCRIPT=${VAL[3]}

# Autenticação
USERNAME=${VAL[4]}
PASSWORD=${VAL[5]}
SSH_KEY=${VAL[6]}
ROOT_RUN=${VAL[7]}
ROOT_PASSWORD=${VAL[8]}

# IPs/Hostname
HOST_FILE=${VAL[9]}
HOST_LIST=$(cat $HOST_LIST | tr '\n' ' ')
IP_START=${VAL[10]}
IP_END=${VAL[11]}

# Opções
EXIT_ERR=${VAL[13]}
LOG=${VAL[14]}
FAIL=${VAL[15]}
COMPRESS_LOG=${VAL[16]}
NOTIFICATION=${VAL[17]}
EOF
            # Restaura o delimitador
            unset IFS

            ;;
    esac

    # Encerra o subshell
    exit 0
}


function exec_cmd()
{
	# Variaveis locais
	local ip_s ip_e range
	local item=0
	local f=0 c=0 s=0 a=0 cp=0 e=0 A="@"
	local stdout stdfail yad_opt set_err
	local STATUS=""
	
	# Local dos binários	
	local SCP="$(which scp)"
	local SSH="$(which ssh)"
	local SSHP="$(which sshpass)"
	
	# Cria os recipientes do projeto
	cp -R "$_SCRIPT" "$_PROJECT" "$TMP_PROJECT"		# Copia os arquivos para a pasta temporária
	cp "$_P_SCRIPT" "$TMP_PROJECT/${_PROJECT##*/}" 	# Copia o script do projeto para a pasta do projeto

	# Verifica as oções selecionadas. 
	[[ "$_CHK_ERR" == ?(TRUE|true) ]] && set_err="set -e"								# Sai imediatamente se houver comandos com status diferentes de zero.
	[[ "$_CHK_LOG" == ?(TRUE|true) ]] && stdout="$LOG" || stdout=/dev/null				# Descritor da saida padrão
	[[ "$_CHK_FAIL" == ?(TRUE|true) ]] && stdfail="$LOG_FAIL" || stdfail=/dev/null		# Gerar LOG de Malsucedidos
	[[ "$_CHK_NOTIFICATION" == ?(TRUE|true) ]] && yad_opt="--auto-close"				# Fecha automaticamente janela de progresso. 
	
	# Verifica o tipo de autenticação e aplica as opções (OPTS) do comando ssh|scp
	# OPTS1 - Parâmetro do comando 'sshpass' contendo a senha.
	# OPTS2 - Parâmetros do comando 'ssh'
	#		  -i '$_SSH_KEY' - Autenticação utilzando uma chave pública
	#		  -o StrictHostKeyCheking=no - Desabilita a verificação rigorosa da chave do host
	#		  -o ConnectTimeout - Tempo limite de tentativa de conexão.
	# OPTS3 - Senha do root
	[[ "$_CHK_ROOT_RUN"  == ?(TRUE|true) ]] && OPTS3="echo -e '$_ROOT_PASS' | sudo -S"	# Rediciona senha (root) para o stdin do sudo
	[ "$_SSH_KEY" ] && { unset SSHP OPTS1 A _USER ; OPTS2="-i '$_SSH_KEY' -o StrictHostKeyChecking=no -o ConnectTimeout=$TIMEOUT"; } \
					|| { OPTS1="-p $_PASS"; OPTS2="-o StrictHostKeyChecking=no -o ConnectTimeout=$TIMEOUT"; }

# Gera script temporáro.
# No script contém as chamadas aos comandos/scripts do usuário e debug.
# Ordem da execução: Comandos, Script, Projeto [Script]
cat > "$TMP_SCRIPT" << EOF
#!/bin/bash
#
# Script ${TMP_SCRIPT##*/}
# Script gerado automaticamente para iniciar a execução dos comandos/scripts
# Ordem de execução
# Suprime erros
exec 2>/dev/null
# Debug Erro: $_CHK_ERR
# comando
$set_err
# Comandos
$_COMMAND

# Script
cd "$TMP_PROJECT"
./"${_SCRIPT##*/}" 

# Projeto
cd "$TMP_PROJECT/${_PROJECT##*/}"
./"${_P_SCRIPT##*/}"

#FIM
exit 0
EOF
	# Permissão de execução.
	chmod +x "$TMP_SCRIPT"
	
	# Registra o inicio da tarefa
	START_RUN="$(date)"
	
	# Lê o total de 'Hostnames/IPs'
	local total=$(cat $TMP_HOSTS | wc -l)

	# Cria arquivo de log
	create_log "$stdfail" "Conexões Malsucedidas:\n"
	
	# Lê todos os hosts configurados.
	for host in $(cat $TMP_HOSTS)
	do
		[ $item -eq 0 ] && echo -e "# Inicializando...\n# ------------------------------"
		echo -n "# Conectando $host... "
		# Testa a conexão com a porta do 'host' remoto por um periodo de N'segundos
		# Valor de 'N' está armazenado em na variavel 'TIMEOUT'
		if echo "exit" | nc -w $TIMEOUT $host $PORT &>/dev/null; then
			echo "[CONECTADO]"		# Porta ativa
		
			echo -n "# Autenticando usuário '$_USER'... "
			# Testa a autenticação do usuário.
			if $SSHP $OPTS1 $SSH $OPTS2 $_USER$A$host exit 0 &>/dev/null; then
				echo "[AUTENTICADO]"	# Autenticação válida

				# Cria arquivo de log passando como paramêtro o 'host' atual.
				create_log "$stdout" "Computador: $host\nDetalhes:\n"
				echo -n "# Copiando projeto/script... "

				# Inicia a cópia  do(s) projeto(s) ou script(s) para o host remoto.
				if $SSHP $OPTS1 $SCP $OPTS2 -r $TMP_PROJECT $_USER$A$host:$TMP_REMOTE &>/dev/null; then
					echo "[OK]"		# 0 - Sucesso na copia
					echo -n "# Executando... "

					# Realiza o login no host, executa o script temporário que faz chamada aos scripts pré-configurados.
					$SSHP $OPTS1 $SSH $OPTS2 $_USER$A$host $OPTS3 $TMP_SCRIPT | create_log "$stdout"	# Gera o log
					if [ ${PIPESTATUS[0]} -eq 0 ]; then
						echo "[OK]"; ((s++))	#  Incrementa o valor de 's' (sucesso)'
					else
						# Salva o status e incrementa o valor de 'e' (execução) 
						echo "[ERRO NA EXECUÇÃO]"; STATUS="$host - [EXECUCAO]"; ((e++)); f=1
					fi
				else
					# Salva o status e incrementa o valor de 'cp' (cópia) 
					echo "[ERRO NA COPIA]"; STATUS="$host - [COPIA]"; ((cp++)); f=1
				fi
			else
				# Salva o status e incrementa o valor de 'a' (Autenticação) 
				echo "[ACESSO NEGADO]"; STATUS="$host - [AUTENTICACAO]"; ((a++)); f=1
			fi
		else
				# Salva o status e incrementa o valor de 'c' (Conexão) 
				echo "[FALHOU]"; STATUS="$host - [CONEXAO]"; ((c++)); f=1
		fi
		
		# Se houve falha, grava status no log
		[ $f -eq 1 ] && { echo "$STATUS" | create_log "$stdfail"; f=0; }

		echo "# ------------------------------"
		((item++))	# Incrementa o valor de item

		# Imprime detalhes 
		if [ $item -eq $total ]; then
			echo "# Processo concluído."
			echo "# Total de Hosts: $total"
			echo "# Sucesso: $s"
			echo "# Erro de Conexão: $c"
			echo "# Erro de autenticação: $a"
			echo "# Erro de Cópia: $cp"
			echo "# Erro de execução: $e"
			echo "# Total de Erro(s): $(($c+$a+$cp+$e))"
		fi
	# Imprime o progresso no 'text-info' do yad
	done | yad --title="$SCRIPT" \
				--text="Executando...." \
				--center \
				--fixed \
				--width=500 --height=500 \
				--progress \
				--pulsate \
				--auto-kill \
				$yad_opt \
				--log-expanded \
				--enable-log="Detalhes:" 

	# Registra o fim da tarefa
	END_RUN="$(date)"

	# Verifica se opção para compactar log foi selecionada.
	if [[ $_CHK_COMPRESS_LOG == ?(TRUE|true) ]]; then
		# Salva o nome do arquivo com o 'Prefixo' especificado.
		# Se 'Prefixo' for omitido, salva com o nome padrão (Nome do Script)"
		TAR_FILE="${PREFIX_COMPRESS:-$SCRIPT}.tar"	#	Insere extensão '.tar'
		# Cria o arquivo tar com o nome especificado em 'TAR_FILE', inserindo os arquivos armazenados em 'LOG' e 'LOG_FAIL'
		# Compacta arquivo para tar.gz  e remove o arquivo '.tar'
		tar -cf "$TAR_FILE" "$LOG" "$LOG_FAIL" && gzip -9f "$TAR_FILE" && rm -f "$TAR_FILE"
		TAR_FILE+=.gz	# Incrementa extensao '.gz' no final do nome
	fi

	# Verfica se 'Notificação está habilitada.
	if [[ $_CHK_NOTIFICATION == ?(TRUE|true) ]]; then
		# Envia notificação ao usuário.
		notify-send --app-name="$SCRIPT" --icon=gtk-execute "$SCRIPT" "Tarefa concluída !!!\nPara: $FROM\nPerfil: $_PROFILE"
		send_email	# Chama a função para enviar e-mail.
	fi
}

function create_log()
{
    local out="$1"	# caminho/arquivo
    local log_name="$(basename "$out")"		# Nome do arquivo.
	
	# Se a função só possuir 2>= argumentos, cria o arquivo de log com as informações
	# iniciais e sai da função. Caso contrário, Lê os dados da entrada padrão.
    if [ $# -gt 1 ]; then
		cat >> "$out" << EOF
=====================================================================================
LOG: $log_name
Data: $(date +'%A, %d de %B de %Y')
Hora: $(date +%T)

$(echo -e "$2")
EOF
	else
		# Lê os dados da entrada padrão e grava no arquivo '$out'
    	while read line; do
cat >> "$out" << EOF
$line
EOF
		done
	fi
	
	# status
	return 0
}

function load_conf()
{
 	# Se arquivo existir, lê as suas configurações.
	if [ -e "$CONF" ]; then
		local FILECONF="$(basename "$CONF")"	# Nome do arquivo

		# Lê os valores das variaveis
		FROM=$(egrep -m1 "^[[:blank:]]*FROM" "$CONF" | cut -d'=' -f2)
		TO=$(egrep -m1 "^[[:blank:]]*TO" "$CONF" | cut -d'=' -f2)
		SUBJECT=$(egrep -m1 "^[[:blank:]]*SUBJECT" "$CONF" | cut -d'=' -f2)
		ATTACH_LOG=$(egrep -m1 "^[[:blank:]]*ATTACH_LOG" "$CONF" | cut -d'=' -f2)
		MESSAGE=$(egrep -m1 "^[[:blank:]]*MESSAGE" "$CONF" | cut -d'=' -f2)
		SRV_SMTP=$(egrep -m1 "^[[:blank:]]*SRV_SMTP" "$CONF" | cut -d'=' -f2)
		XUSER=$(egrep -m1 "^[[:blank:]]*XUSER" "$CONF" | cut -d'=' -f2)
		XPASS=$(egrep -m1 "^[[:blank:]]*XPASS" "$CONF" | cut -d'=' -f2)
		PORT=$(egrep -m1 "^[[:blank:]]*PORT" "$CONF" | cut -d'=' -f2)
		TIMEOUT=$(egrep -m1 "^[[:blank:]]*TIMEOUT" "$CONF" | cut -d'=' -f2)
		TMP_REMOTE=$(egrep -m1 "^[[:blank:]]*TMP_REMOTE" "$CONF" | cut -d'=' -f2)
		LOG_DIR=$(egrep -m1 "^[[:blank:]]*LOG_DIR" "$CONF" | cut -d'=' -f2)
		LOG_FAIL_DIR=$(egrep -m1 "^[[:blank:]]*LOG_FAIL_DIR" "$CONF" | cut -d'=' -f2)
		PREFIX_COMPRESS=$(egrep -m1 "^[[:blank:]]*PREFIX_COMPRESS" "$CONF" | cut -d'=' -f2)
		
		# Se a variavel não for nula, verifica seu valor.
		# Se o valor for inválido, imprime mensagem de erro e retorna para as configurações.
		[[ $FROM && ! $FROM =~ ^.*@.*$ ]] && message.error "Arquivo: $FILECONF\nDe: '$FROM' Endereço de email inválido." 2
		[[ $TO && ! $TO =~ ^.*@.*$ ]] && message.error "Arquivo: $FILECONF\nPara: '$TO' Endereço de email inválido." 2
		[[ ! $PORT == ?(+)+([0-9]) ]] && message.error "Arquivo: $FILECONF\nPorta: '$PORT' Porta inválida." 2
		[[ ! $TIMEOUT == ?(+)+([0-9]) ]] && message.error "Arquivo: $FILECONF\nTempo limite: '$TIMEOUT' Valor do tempo inválido." 2
		[[ ! -e $LOG_DIR ]] && message.error "Arquivo: $FILECONF\nLOG: '$LOG_DIR' Diretório não encontrado." 2
		[[ ! -e $LOG_FAIL_DIR ]] && message.error "Arquivo: $FILECONF\nMausucedidos: '$LOG_FAIL_DIR' Diretório não encontrado." 2
	
		# Locais onde seram salvos os arquivos de LOG	
		LOG="$LOG_DIR/$SCRIPT.log"
		LOG_FAIL="$LOG_FAIL_DIR/$SCRIPT.log.1"
	else
		# Arquivo não exite.
		# Cria um arquivo com as configurações padrão.
		save_conf
	fi
}

function save_conf()
{

# Salva as configurações no arquivo.
# Se o valor dos vetores de 'OPTCONF' for nulo, salva o valor padrão dos campos obrigatórios.
	cat > "$CONF" << EOF
# $SCRIPT
# Arquivo de configuração

# Email
# FROM - Endereço de email do remetente
# TO - Endereço de mail do destinatário
# SUBJECT - Campo que define o assunto do email.
# ATTACH_LOG - Enviar LOG como anexo
# MESSAGE - Mensagem que será enviada.
FROM=${OPTCONF[1]}
TO=${OPTCONF[2]}
SUBJECT=${OPTCONF[3]}
ATTACH_LOG=${OPTCONF[4]:-FALSE}
MESSAGE=${OPTCONF[5]}

# Autenticação
# SRV_STMP - Endereço do servidor SMTP de email. O endereço seguido do prefixo da porta de conexão. <server:porta>
#			 Exemplo: stmp.gmail.com:587
#					  Observação: Em alguns casos o número da 'porta' é opcional.
#			 ATENCAO: É necessário configurar o email para aceitar SMTP com POP habilitado.
# XUSER - Nome do usuário para autenticação. Essa opção depende do serviço de email utilizado.
#		  Exemplo: meu.endereco@gmail.com - Utilizando o email completo.
#				   meu.endereco			  - O nome antes do @
# XPASS - Senha de acesso. (utilizada para acessar o endereço email)
SRV_SMTP=${OPTCONF[6]}
XUSER=${OPTCONF[7]}
XPASS=${OPTCONF[8]}

# Conexão
# PORT - Porta de conexão com o 'host' remoto e utilizada pelo serviço do ssh. (padrão: 22)
# TIMEOUT - Tempo limite de tentativa de conexão com o host.
PORT=$(echo ${OPTCONF[10]:-22} | cut -d',' -f1)
TIMEOUT=$(echo ${OPTCONF[11]:-5} | cut -d',' -f1)

# Remoto
# TMP_REMOTE - Caminho da pasta remota para onde será copiados os coamndos/scripts
TMP_REMOTE=${OPTCONF[14]:-/tmp}

# Log
# LOG_DIR - Diretório onde será salvo o arquivo de LOG
# LOG_FAIL_DIR - Diretório onde será salvo o arquivo de FALHAS/LOG
LOG_DIR=${OPTCONF[16]:-$PWD}
LOG_FAIL_DIR=${OPTCONF[17]:-$PWD}

# Compactação
# PREFIX_COMPRESS - Prefixo nome do arquivo compactado.
PREFIX_COMPRESS=${OPTCONF[20]}
#FIM
EOF

}

function settings()
{
	# Exibe a janela de configurações e aguarda status de retorno
	# <botão>:status
	# Salva:0
	# Fechar|Sair:1
	if OPTCONF="$(yad --title="Configurações" \
				--image=gtk-preferences \
				--center \
				--fixed \
				--columns=2 \
				--width=850 --height=550 \
				--button='Salvar!gtk-save!Salva as alterações.':0 \
				--button='Sair!gtk-quit!Sai sem salvar':1 \
				--form \
				--field='<b>Notificação</b>':LBL '' \
				--field='De (Email):' "$FROM" \
				--field='Para: (Email):' "$TO" \
				--field='Assunto:' "$SUBJECT" \
				--field='Enviar LOG em anexo (Habilitar "Compactar LOG")':CHK "$ATTACH_LOG" \
				--field='Mensagem:':TXT "$MESSAGE" \
				--field='Servidor SMTP:' "$SRV_SMTP" \
				--field='Usuário:' "$XUSER" \
				--field='Senha:':H "$XPASS" \
				--field='<b>Conexão</b>':LBL '' \
				--field='Porta:':NUM $PORT'!1..65536!1' \
				--field='Tempo limite (secs):':NUM $TIMEOUT'!1..30!1' \
				--field='':LBL '' \
				--field='<b>Remoto</b>':LBL '' \
				--field="Diretorio:":CDIR "$TMP_REMOTE" \
				--field='<b>Salvar LOG</b>':LBL '' \
				--field='LOG:':DIR "$LOG_DIR" \
				--field='Mausucedidos:':DIR "$LOG_FAIL_DIR" \
				--field='':LBL '' \
				--field='<b>Compactação</b>:':LBL '' \
				--field='Prefixo:' "$PREFIX_COMPRESS" \
				--field='<b>Agendamentos</b>':LBL '' \
				--field='Visualizar/Adicionar!gtk-index!Visualizar/Editar agendamentos':BTN "./shexec.sh --schedule" \
				--field='':LBL '' \
				--field='':LBL '' \
				--field='':LBL '')"; then
				
				# Obtem o valor dos campos.
				IFS='|'; OPTCONF=($OPTCONF); unset IFS
			
				# Salva as configurações	
				save_conf
			fi
}

function send_email()
{
	local SEND="$(which sendemail)"		# Obtem o binário
	local ATTACH=""						# Anexo
	
	# Notificação, salva o nome do arquivo a ser enviado como anexo. 
	[[ $ATTACH_LOG == ?(TRUE|true) ]] && ATTACH="$TAR_FILE"

	# Valor padrão para mensagem e assunto do corpo do email.	
	SUBJECT=${SUBJECT:-$SCRIPT - $_PROFILE}
	MESSAGE+="\n\nProcesso concluido.\nPerfil: $_PROFILE\nIniciado: $START_RUN\nConcluido: $END_RUN"
	
	# Envia email em segundo plano e rediciona a saida para o log
	$SEND -f "$FROM" -t "$TO" -u "$SUBJECT" -m "$MESSAGE" -s "$SRV_SMTP" -xu "$XUSER" -xp "$XPASS" -a "$ATTACH" | create_log "$LOG" &
	pid=$!	# Salva o 'PID' do comando
	
	# Atualiza a barra de progresso enquanto o 'pid' do processo existir.
	while ps -q $pid &>/dev/null; do 
		echo "# Para: $TO\nAnexo: $ATTACH"
		sleep 0.5
	done | yad --title="Enviando email..." \
				--center \
				--fixed \
				--progress \
				--pulsate \
				--auto-close \
				--auto-kill 
}

function set_schedule()
{
	# Variaveis locais
	local OPT
	local CRONTAB="$(which crontab)"
	local CRON_LIST=/tmp/cron.list
	local CRON_SYS=/tmp/cron.sys
	local CRON_OTHER=/tmp/cron.other
	local ch=${ch:-0}	# Status de alteração do agendamento
	
	if [ $ch -eq 0 ]; then
		# Salva a lista de outros agendamentos
		$CRONTAB -l | sed "/$SCRIPT/d" > $CRON_OTHER
		# Salva agendamentos do 'shExec'
		$CRONTAB -l | egrep -v "^$|^[[:blank:]]*#" | grep "$SCRIPT" | sed "s/.*\/\(.*\)*'$/\1 &/g" | \
														  awk '{printf "%s\n%s\n%s\n%s\n%s\n%s\n%s %s %s\n",$1,$3,$2,$4,$5,$6,$7,$8,$9}' > $CRON_SYS
	fi

	# Lê os agendamentos salvos em 'CRON_SYS'
	cat $CRON_SYS | \
		yad --list \
			--title="Agendamentos" \
			--text-align=fill \
			--text="O uso do * (asterisco) serve especificar uma execução constante.\nPor exemplo, se o campo dias do mês conter *, o comando relacionado será\nexecutado todos os dias. Você também pode informar intervalos no\npreenchimento, separando os números de início e fim através de - (hífen).\nPor exemplo, se no campo horas for informado 2-5, o comando relacionado será\nexecutado às 2, 3, 4 e 5 horas. Observação: valores incorretos são substituidos\npelo valor padrão * (asterisco).\n\nLista dos agendamentos disponíveis:" \
			--print-all \
			--editable \
			--center \
			--fixed \
			--width=400 \
			--height=400 \
			--hide-column=7 \
			--button='Adicionar!gtk-add!Adicionar agendamento':2 \
			--button='Salvar!gtk-save!Salvar as alterações.':0 \
			--button='Sair!gtk-quit!Sai sem salvar':1 \
			--column="Perfil" \
			--column="Horas" \
			--column="Minutos" \
			--column="Dia do mês" \
			--column="Mẽs" \
			--column="Dia da semana" \
			--column="Comando" | tr '|' ' ' | awk '{print $3,$2,$4,$5,$6,$7,$8,$9}' > $CRON_LIST 

	# Salva o status de retorno do yad 
	RETVAL=${PIPESTATUS[1]}	
	
	case $RETVAL in
		0)	# Salvar:0
			# Salva no final do arquivo 'CRON_OTHER' os agendamentos armazenados em 'CRON_LIST'
			cat $CRON_LIST >> $CRON_OTHER
			# Salva os agendamentos
			$CRONTAB "$CRON_OTHER"
			ch=0	# Restaura status 
			;;
		2)	# Adicionar:2
			# Exibe as opções de agendamento e armazena em 'OPT'
			OPT=$(yad --form \
				--title="Agendar tarefa" \
				--center \
				--fixed \
				--width=300 \
				--height=300 \
				--button='Voltar':1 \
				--button='Aplicar!gtk-apply!Inserir item na lista.':0 \
				--field="Perfil:":FL "" \
				--field='Horas':CB $(echo Todas {0..23} | tr ' ' '!') \
				--field='Minutos':CB $(echo Todos {0..59} | tr ' ' '!') \
				--field='Dia do mês':CB $(echo Todos {1..31} | tr ' ' '!') \
				--field='Mês':CB $(echo Todos {1..12} | tr ' ' '!') \
				--field='Dia da semana':CB $(echo Todos {1..7} | tr ' ' '!'))
			
			# Salva status
			RETVAL=$?
	
			# Aplicar:0
			if [ $RETVAL -eq 0 ]; then
				# Converte as expressões 'Todos e Todas' em "*"
				OPT="$(echo $OPT | sed 's/\(Todos\|Todas\)/"*"/g')"
				# Inicia um array em OPT
				IFS='|'; OPT=($OPT); unset IFS
				
				# Verifica a extensão do arquivo de perfil
				if [ "${OPT[0]##*.}" == "shexec" ]; then
						# Salva os parametros e valores do comando 'CMD'
						_CMD="'$PWD/$SCRIPT.sh' --exec '${OPT[0]}'"
						echo "$(basename "${OPT[0]}") ${OPT[2]} ${OPT[1]} ${OPT[*]:3} $_CMD" | tr -d '"' | \
						awk '{printf "%s\n%s\n%s\n%s\n%s\n%s\n%s %s %s\n",$1,$3,$2,$4,$5,$6,$7,$8,$9}' >> $CRON_SYS 
						ch=1	# Status
				else
					# Perfil inválido.
					message.error "Perfil: $(basename "${OPT[0]}") Arquivo de perfil inválido" 0
				fi	
			fi
			;;
		1|252)	# Sair|Fechar
			return 0
			;;
	esac

	# Retorna para o agendamento
	set_schedule
}

function main()
{	
	# Variável local
	local OPT
	load_conf	# Lẽ as configurações

	# Janela principal
	# Contém as configurações de execução.
	# Execução: Comando, Script, Projeto, Projeto [Script]
	# Autenticação: Usuário, Senha, Chave RSA, Executar como root
	# Computadores: Arquivo de hosts, Lista de hosts, Intervalo de IP's
	# Opções: Erro, Gerar LOG, Gerar LOG mausucedido, notifcar
	OPT=$(yad --form  \
				--columns=4 \
				--width=900 \
				--height=100 \
				--center \
				--fixed \
				--text-align=center \
				--image=gtk-execute \
				--button='Executar!gtk-execute!Executa o(s) script(s) ou comando(s).':0 \
				--button='Sair!gtk-quit!Sai do script.':1 \
				--button='Configurações!gtk-preferences!Configurações avançadas.':2 \
				--text="<b>$SCRIPT</b> permite a execução de scripts/comandos em computadores na rede." \
				--title="$SCRIPT - [x_SHAMAN_x]" \
				--field='':LBL '' \
				--field='<b>Execução</b>':LBL '' \
				--field="Comando:" "$_COMMAND" \
				--field='Script:':SFL "$_SCRIPT" \
				--field="Projeto:":CDIR "$_PROJECT" \
				--field="Projeto [Script]:":SFL "$_P_SCRIPT" \
				--field='<b>Obs:</b> Opção "Projeto", requer que o usuário informe\no script que será executado primeiro.':LBL '' \
				--field='':LBL '' \
				--field="Data:":RO "$(date +'%A, %d de %B de %Y')" \
				--field='':LBL '' \
				--field='':LBL '' \
				--field="<b>Autenticação</b>":LBL '' \
				--field="Usuario:" "$_USER" \
				--field="Senha:":H "$_PASS" \
				--field="Chave RSA:":SFL "$_SSH_KEY" \
				--field='Executar como root':CHK $_CHK_ROOT_RUN \
				--field='Senha (root):':H "$_ROOT_PASS" \
				--field='':LBL '' \
				--field="Usuário:":RO "$USER" \
				--field='':LBL '' \
				--field='':LBL '' \
				--field='<b>Computadores</b>':LBL '' \
				--field="Arq. Host:":SFL "$_HOST_FILE" \
				--field="Lista de hosts":BTN "./shexec.sh win_hosts" \
				--field="Intervalo de IPs":LBL '' \
				--field="Inicio": "$_IP_START" \
				--field="Fim": "$_IP_END" \
				--field='':LBL '' \
				--field="Perfil:":RO "$_PROFILE" \
				--field='':LBL '' \
				--field='':LBL '' \
				--field="<b>Opções</b>":LBL '' \
				--field="Fechar conexão se houver erro":CHK $_CHK_ERR \
				--field="Gerar LOG [$SCRIPT.log]":CHK $_CHK_LOG  \
				--field="Gerar malsucedidos [$SCRIPT.log.1]":CHK $_CHK_FAIL \
				--field="Compactar LOG":CHK $_CHK_COMPRESS_LOG \
				--field="Notificar ao terminar":CHK $_CHK_NOTIFICATION \
				--field='Novo!gtk-new!Novo perfil.':BTN "@./shexec.sh profile new" \
				--field='Salvar!gtk-save!Salva as configurações atuais.':BTN "./shexec.sh profile save '%3|%4|%5|%6|%13|%14|%15|%16|%17|%23|%26|%27|%29|%33|%34|%35|%36|%37'" \
				--field='Carregar!gtk-open!Carrega as configurações do perfil salvo.':BTN "@./shexec.sh profile load")
				
				# Status de retorno		
				RETVAL=$?
	
				# Cria um array com os valores inseridos nos campos.
				IFS='|'; OPT=($OPT); unset IFS
				
				# Inicializa os valores
				_COMMAND=${OPT[2]}
				_SCRIPT=${OPT[3]}			
				_PROJECT=${OPT[4]}
				_P_SCRIPT=${OPT[5]}
				_USER=${OPT[12]}
				_PASS=${OPT[13]}
				_SSH_KEY=${OPT[14]}
				_CHK_ROOT_RUN=${OPT[15]}
				_ROOT_PASS=${OPT[16]}
				_HOST_FILE=${OPT[22]}
				_IP_START=${OPT[25]}
				_IP_END=${OPT[26]}
				_PROFILE=${OPT[28]}
				_CHK_ERR=${OPT[32]}
				_CHK_LOG=${OPT[33]}
				_CHK_FAIL=${OPT[34]}
				_CHK_COMPRESS_LOG=${OPT[35]}
				_CHK_NOTIFICATION=${OPT[36]}
	
	# Seleciona a opção
	case $RETVAL in
		0)
			check_fields
			exec_cmd
			;;
		2)
			load_conf
			settings
			;;
		1|252)
			_exit
			;;
	esac
	
	# retorna para a função principal.
	main
	
}


# Se o script for iniciado sem parâmetros, define o RUNLEVEL=7 e executa a função principal
# RUNLEVEL altera a saida das mensagens de erro do script.
# 7 - Modo Gráfico
# 3 - Modo texto.
[ $# -eq 0  ] && { RUNLEVEL=7; main; }

RUNLEVEL=3

# Trata os parâmetros do script
case $1 in
    profile)
        # Passa os parâmetros da função.
        profile ${*:2}
       ;;
    win_hosts)
		# Lista de hots
        win_hosts
        ;;
	-s|--schedule)
		# Agendamentos
		RUNLEVEL=7
		set_schedule
		;;
	-w|--settings)
		# Configurações
		RUNLEVEL=7
		load_conf
		settings
		;;
	-h|--help)
		# Ajuda
		echo "Uso: $SCRIPT [OPCOES] [ARQUIVO]"
		echo
		echo "Script para execução de comandos/scripts em 'hosts' na rede."
		echo
		echo "-e, --exec                       Executa as tarefas do perfil."
		echo "-c, --check-config               Checa as configurações do arquivo 'shexec.conf'"
		echo "-p, --check-profile <perfil>     Verifica as configurações do perfil."
		echo "-s, --schedule                   Acessa a GUI de agendamentos."
		echo "-w, --settings                   Acessa a GUI de configurações."
		echo "-u, --edit                       Editar arquivo de configuração 'shexec.conf'."
		echo "-o, --open <perfil>              Abre o perfil para edição."                       
		echo "-h, --help                       Obter mais informações."
		;;
	-e|--exec)
		# Executar perfil
		[ "$2" ] && { load_profile "$2"; load_conf; check_fields; exec_cmd; } || echo "$SCRIPT: Erro: Requer arquivo de perfil."
		;;
	-c|--check-config)
		# Checar configurações
		load_conf; echo "[OK]"
		;;
	-p|--check-profile)
		# Verificar arquivo de perfil
		[ "$2" ] && { load_profile "$2"; check_fields; } || { echo "$SCRIPT: Erro: Requer arquivo de perfil."; }
		;;
	-u|--edit)
		# Editar
		echo -e "Escolha com qual editor deseja abrir o arquivo.\n"
		exec 2>&1	
		select edit in $(update-alternatives --list editor)
		do 
			[ "$edit" ] && { eval $edit "$CONF"; break; }
		done
		;;
	-o|--open)
		# Abrir
		[ "$2" ] && { load_profile "$2"; main; } || { echo "$SCRIPT: Erro: Requer arquivo de perfil."; }
		;;
	*)
		# Default
		echo "$SCRIPT: '$*' opção inválida."
		echo "Tente '$SCRIPT --help' para mais informações."
	;;
esac

# Limpa cache e sai do script
_exit 

# Vulhunter

Vulhunter é um agente de IA especializado em segurança de software, projetado para detectar e corrigir automaticamente vulnerabilidades em projetos Java hospedados no GitHub. O agente utiliza o Trivy para análise de vulnerabilidades e é capaz de atualizar automaticamente as dependências vulneráveis.

## Características

- Clonagem automática de repositórios GitHub
- Análise de vulnerabilidades usando Trivy
- Atualização automática de dependências no pom.xml
- Criação automática de branches e PRs com correções
- Suporte a diferentes codificações de arquivo
- Gerenciamento automático de arquivos temporários

## Pré-requisitos

- Python 3.x
- Trivy (instalado e no PATH do sistema)
- Git
- Acesso à API do Google (para o modelo Gemini)

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/vulhunter_agent.git
cd vulhunter_agent
```

2. Instale as dependências:
```bash
pip install google-adk chardet packaging GitPython
```

3. Configure a chave da API do Google:
   - Crie um arquivo `.env` na raiz do projeto
   - Adicione sua chave da API:
     ```
     GOOGLE_API_KEY="SUA_API_KEY_AQUI"
     ```

## Uso

### Interface Visual de Debug

Para iniciar a interface visual de debug do agente, use o comando:

```bash
adk web
```

Isto iniciará um servidor web local que fornece:

1. **Playground Interativo**:
   - Interface visual para testar o agente
   - Visualização em tempo real das respostas
   - Histórico de conversas

2. **Ferramentas de Debug**:
   - Visualização das chamadas de função
   - Logs detalhados
   - Estado do agente em tempo real

Acesse a interface através do navegador em `http://localhost:8000`

## Estrutura do Projeto

```
vulhunter_agent/
├── vulhunter/
│   ├── __init__.py
│   ├── agent.py          # Configuração principal do agente
│   └── function_tools.py # Implementação das ferramentas
├── .env                  # Configurações de ambiente
└── README.md            # Esta documentação
```

## Comportamento do Agente

1. Clone do Repositório:
   - Clona o repositório em uma pasta temporária
   - Gerencia automaticamente a limpeza do diretório

2. Análise de Vulnerabilidades:
   - Usa o Trivy para análise completa
   - Gera relatório detalhado em JSON

3. Atualização de Dependências:
   - Analisa o pom.xml do projeto
   - Identifica dependências vulneráveis
   - Seleciona versões corrigidas compatíveis
   - Atualiza mantendo a compatibilidade de versões

4. Gestão de Alterações:
   - Cria uma nova branch para as correções
   - Commita as alterações com mensagens detalhadas
   - Faz push para o repositório remoto

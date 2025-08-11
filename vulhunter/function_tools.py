import json
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any
from io import BytesIO

import chardet
import git
from packaging import version

def severity_level(severity: str) -> int:
    """
    Converte a severidade em um número para comparação.
    
    Args:
        severity (str): A severidade da vulnerabilidade (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
        
    Returns:
        int: O nível numérico da severidade (4 para CRITICAL, 3 para HIGH, etc.)
    """
    levels = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0
    }
    return levels.get(severity.upper(), 0)


def create_temp_directory() -> str:
    """
    Cria um diretório temporário para o projeto dentro da pasta vulhunter.

    Returns:
        str: O caminho para o diretório temporário criado.
    """
    vulhunter_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = os.path.join(vulhunter_dir, "tmp")
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

def clone_repository(repo_url: str, local_path: Optional[str] = None) -> str:
    """
    Clona um repositório do GitHub para um diretório local.

    Args:
        repo_url (str): A URL do repositório GitHub para clonar.
        local_path (Optional[str]): O caminho local onde o repositório será clonado. Se None, será usado um diretório temporário.

    Returns:
        str: O caminho para o repositório clonado localmente.
    """
    try:
        if local_path is None:
            temp_dir = create_temp_directory()
            local_path = os.path.join(temp_dir, "cloned_project")
            
        if os.path.exists(local_path):
            shutil.rmtree(local_path)
            
        print(f"Clonando {repo_url} para {local_path}...")
        git.Repo.clone_from(repo_url, local_path)
        print("Repositório clonado com sucesso.")
        return local_path
    except Exception as e:
        return f"Erro ao clonar o repositório: {e}"
    
def run_trivy_scan(project_path: str) -> str:
    """
    Executa o Trivy para escanear um projeto Java em busca de vulnerabilidades.

    Args:
        project_path (str): O caminho para o projeto local a ser escaneado.

    Returns:
        str: O caminho para o arquivo de relatório JSON gerado pelo Trivy.
    """
    report_dir = os.path.join(os.path.dirname(project_path), "trivy_report")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "trivy_report.json")
    command = [
        "trivy", "fs",
        "--format", "json",
        "--output", report_path,
        project_path
    ]
    try:
        print("Executando o Trivy para análise de vulnerabilidades...")
        # Aumente o timeout se necessário para projetos grandes
        subprocess.run(command, check=True, timeout=300)
        print(f"Relatório do Trivy gerado com sucesso em: {report_path}")
        return report_path
    except FileNotFoundError:
        return "Erro: O Trivy não está instalado ou não está no PATH do sistema."
    except subprocess.CalledProcessError as e:
        return f"Erro ao executar o Trivy: {e}"
    except subprocess.TimeoutExpired:
        return "Erro: A execução do Trivy demorou mais do que o esperado (timeout)."
    
def parse_trivy_and_update_pom(trivy_report_path: str, pom_xml_path: str) -> list[str]:
    """
    Analisa o relatório JSON do Trivy, atualiza as dependências vulneráveis no pom.xml
    e retorna uma lista das alterações feitas.

    Args:
        trivy_report_path (str): O caminho para o relatório JSON do Trivy.
        pom_xml_path (str): O caminho para o arquivo pom.xml.

    Returns:
        list[str]: Uma lista de strings descrevendo as correções aplicadas.
    """
    try:
        # Lê o relatório Trivy
        with open(trivy_report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)

        # Tenta detectar a codificação do arquivo pom.xml
        with open(pom_xml_path, 'rb') as f:
            raw_data = f.read()
            detected = chardet.detect(raw_data)
            encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
            
        print(f"Codificação detectada no pom.xml: {encoding}")

        # Encontra o resultado específico do pom.xml
        pom_result = None
        for result in report["Results"]:
            if result.get("Target") == "pom.xml" and "Vulnerabilities" in result:
                pom_result = result
                break

        if not pom_result:
            return ["Nenhuma vulnerabilidade encontrada no pom.xml."]

        # Monta um dicionário de correções agrupando por pacote
        corrections: Dict[str, Dict[str, Any]] = {}
        for vuln in pom_result["Vulnerabilities"]:
            pkg_name = vuln.get("PkgName")
            if pkg_name and "InstalledVersion" in vuln and "FixedVersion" in vuln:
                severity = vuln.get("Severity", "UNKNOWN")
                current_version = vuln["InstalledVersion"]
                # Para versões múltiplas, pega a primeira compatível
                fixed_versions = [v.strip() for v in vuln["FixedVersion"].split(",")]
                
                # Tenta encontrar a versão mais próxima da atual
                current_major = version.parse(current_version).major
                compatible_version = None
                
                for ver in fixed_versions:
                    try:
                        if version.parse(ver).major == current_major:
                            compatible_version = ver
                            break
                    except version.InvalidVersion:
                        continue
                
                if not compatible_version and fixed_versions:
                    compatible_version = fixed_versions[0]
                
                # Guarda informações detalhadas sobre a vulnerabilidade
                if pkg_name not in corrections or severity_level(severity) > severity_level(corrections[pkg_name]["severity"]):
                    corrections[pkg_name] = {
                        "current_version": current_version,
                        "fixed_version": compatible_version,
                        "severity": severity,
                        "cve": vuln.get("VulnerabilityID", "Unknown"),
                        "description": vuln.get("Description", "No description available").split('\n')[0]  # Primeira linha da descrição
                    }

        if not corrections:
            return ["Vulnerabilidades encontradas, mas sem versões de correção disponíveis."]

        # Lê o conteúdo do pom.xml com a codificação detectada
        with open(pom_xml_path, 'r', encoding=encoding) as f:
            content = f.read()
            
        ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
        tree = ET.ElementTree(ET.fromstring(content))
        root = tree.getroot()
        namespace = {'m': 'http://maven.apache.org/POM/4.0.0'}

        applied_fixes = []
        dependencies = root.findall('.//m:dependency', namespace)
        for dep in dependencies:
            groupId_element = dep.find('m:groupId', namespace)
            artifactId_element = dep.find('m:artifactId', namespace)
            version_element = dep.find('m:version', namespace)
            
            if groupId_element is not None and artifactId_element is not None and version_element is not None:
                pkg_name = f"{groupId_element.text}:{artifactId_element.text}"
                if pkg_name in corrections:
                    old_version = version_element.text
                    correction_info = corrections[pkg_name]
                    new_version = correction_info["fixed_version"]
                    
                    if old_version != new_version and new_version is not None:
                        version_element.text = new_version
                        applied_fixes.append(
                            f"Corrigido: {pkg_name}\n"
                            f"  Versão atual: {old_version}\n"
                            f"  Nova versão: {new_version}\n"
                            f"  Severidade: {correction_info['severity']}\n"
                            f"  CVE: {correction_info['cve']}\n"
                            f"  Descrição: {correction_info['description']}"
                        )

        if applied_fixes:
            # Converte a árvore XML para string
            from io import BytesIO
            bio = BytesIO()
            tree.write(bio, encoding=encoding, xml_declaration=True)
            xml_content = bio.getvalue().decode(encoding)
            
            # Salva o conteúdo no arquivo com a codificação correta
            with open(pom_xml_path, 'w', encoding=encoding) as f:
                f.write(xml_content)

        return applied_fixes if applied_fixes else ["Nenhuma correção foi aplicada."]

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        return [f"Erro ao processar o pom.xml: {e}\nDetalhes: {error_details}"]
    
def cleanup_temp_directory() -> str:
    """
    Limpa o diretório temporário criado para o projeto dentro da pasta vulhunter.

    Returns:
        str: Mensagem indicando o resultado da operação.
    """
    vulhunter_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = os.path.join(vulhunter_dir, "tmp")
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            return f"Diretório temporário {temp_dir} foi removido com sucesso."
        return f"Diretório temporário {temp_dir} não encontrado."
    except Exception as e:
        return f"Erro ao remover diretório temporário: {e}"

def commit_and_push_changes(repo_path: str, branch_name: str, commit_message: str) -> str:
    """
    Cria uma nova branch, commita as alterações e faz o push para o repositório remoto.
    Após o push, limpa o diretório temporário.

    Args:
        repo_path (str): O caminho para o repositório local.
        branch_name (str): O nome da nova branch a ser criada.
        commit_message (str): A mensagem de commit.

    Returns:
        str: Uma mensagem de sucesso ou erro.
    """
    try:
        repo = git.Repo(repo_path)
        
        # Cria e faz checkout para a nova branch
        new_branch = repo.create_head(branch_name)
        new_branch.checkout()

        # Adiciona o arquivo pom.xml modificado
        repo.index.add(['pom.xml'])

        # Faz o commit
        repo.index.commit(commit_message)

        # Faz o push da nova branch para a origem (origin)
        origin = repo.remote(name='origin')
        origin.push(f"{branch_name}:{branch_name}")

        return f"Sucesso! As correções foram enviadas para a branch '{branch_name}'."
    except Exception as e:
        return f"Erro durante o processo de git: {e}"
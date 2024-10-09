import os
import subprocess
import json
import urllib.request
import platform
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from subprocess import check_output, CalledProcessError,run
from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash
import threading
from dotenv import load_dotenv
from django.contrib.auth import authenticate, login,logout
from django.contrib import messages
import hashlib
from .models import Usuario
from django import forms
from django.contrib.auth.decorators import login_required
load_dotenv()
GH_WINDOWS_PATH = os.getenv('GH_WINDOWS_PATH')  
GH_INSTALLER_URL = os.getenv('GH_INSTALLER_URL')
INSTALLER_FILENAME = os.getenv('INSTALLER_FILENAME')

def check_github_cli_installed_windows():
    if os.path.exists(GH_WINDOWS_PATH):
        print("GitHub CLI is already installed on Windows.")
        return True
    else:
        print("GitHub CLI is not installed on Windows.")
        return False

def check_github_cli_installed_unix():
    try:
        subprocess.run(["which", "gh"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("GitHub CLI is already installed on Linux/MacOS.")
        return True
    except subprocess.CalledProcessError:
        print("GitHub CLI is not installed on Linux/MacOS.")
        return False


def install_github_cli_windows():
    installer_path = os.path.join(os.getcwd(), INSTALLER_FILENAME)
    try:
        print("Downloading GitHub CLI installer for Windows...")
        urllib.request.urlretrieve(GH_INSTALLER_URL, installer_path)
        print("Download complete. Running installer...")

        subprocess.run(["msiexec", "/i", installer_path, "/quiet", "/norestart"], check=True)
        print("GitHub CLI installation complete on Windows.")
    except Exception as e:
        print(f"Failed to download or install GitHub CLI on Windows: {e}")


def install_github_cli_linux():
    try:
        print("Installing GitHub CLI on Linux...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "gh"], check=True)
        print("GitHub CLI installation complete on Linux.")
    except subprocess.CalledProcessError as e:
        print(f"Error during installation on Linux: {e}")

def ensure_github_cli_installed():
    system = platform.system()

    if system == "Windows":
        if not check_github_cli_installed_windows():
            install_github_cli_windows()
        else:
            print("GitHub CLI is ready to use on Windows.")
    
    elif system == "Linux":
        if not check_github_cli_installed_unix():
            install_github_cli_linux()
        else:
            print("GitHub CLI is ready to use on Linux.")
    
    elif system == "Darwin":  
        if not check_github_cli_installed_unix():
            print("Please install GitHub CLI manually on MacOS by running `brew install gh`.")
        else:
            print("GitHub CLI is ready to use on MacOS.")
    
    else:
        print("Unsupported operating system.")

def check_authentication():
    try:
        output = check_output([GH_WINDOWS_PATH, "auth", "status"]).decode('utf-8')
        return True
    except CalledProcessError:
        return False
def authenticate_github_cli(token):
    try:
        print("Initiating GitHub CLI authentication...")
        subprocess.run([GH_WINDOWS_PATH, "auth", "login", "--with-token"], input=token.encode(), check=True)
        print("Authentication successful.")
    except CalledProcessError as e:
        print(f"Authentication failed: {str(e)}")



def connect_to_codespace(codespace_name):
    try:
        print(f"Connecting to the Codespace: {codespace_name}...")
        subprocess.run([GH_WINDOWS_PATH, "codespace", "ssh", "-c", codespace_name], check=True)
        print(f"Connection to {codespace_name} established.")
    except CalledProcessError as e:
        print(f"Error connecting to Codespace: {str(e)}")

@login_required
def list_codespaces(request):
    ensure_github_cli_installed()

    if not check_authentication():
        return redirect('authenticate_github_cli')

    try:
        output = check_output([GH_WINDOWS_PATH, "codespace", "list", "--json", "name"]).decode('utf-8')
    except CalledProcessError as e:
        return render(request, "error.html", {"message": f"Error listing codespaces: {str(e)}"})
    except FileNotFoundError:
        return render(request, "error.html", {"message": "GitHub CLI (gh) is not installed or not found."})

    codespaces = json.loads(output)

    if request.method == "POST":
        selected_code = request.POST.get('codespace')

        # Ejecutar la conexión en un hilo separado
        connection_thread = threading.Thread(target=connect_to_codespace, args=(selected_code,))
        connection_thread.start()

        return render(request, 'connecting.html',{'codespaces':selected_code})

    return render(request, 'list_codespaces.html', {'codespaces': codespaces})
@login_required
def authenticate_github_cli_view(request):

    try:
        usuario=request.user
        token=usuario.token
    except Usuario.DoesNotExist:
        token=None
    if token:
        authenticate_github_cli(token)
        return redirect('list_codespaces')

#LOGIN
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username") 
        password = request.POST.get("password")  

        usuario = authenticate(username=username, password=password)  
        if usuario is not None:
            login(request, usuario)
            return redirect('list_codespaces') 
        else:
            return render(request, 'login.html', {'error': 'Usuario o contraseña inválidos'})

    return render(request, 'login.html')
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        token = request.POST.get("token")
        password = request.POST.get("password")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()


        if Usuario.objects.filter(token=token).exists():
            messages.error(request, "Token ya está en uso.")
            return render(request, "register.html")

        usuario = Usuario(username=username, email=email, token=token, password=hashed_password)
        usuario.save()
        messages.success(request, "Usuario creado exitosamente.")
        return redirect('login')  

    return render(request, "register.html")
class CustomPasswordChangeForm(forms.Form):
    username = forms.CharField(label="Nombre de usuario", max_length=150)
    new_password = forms.CharField(widget=forms.PasswordInput, label="Nueva contraseña")

def change_password_view(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            new_password = form.cleaned_data.get('new_password')

            try:
                user = Usuario.objects.get(username=username)
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)  

                messages.success(request, 'La contraseña ha sido actualizada exitosamente.')
                return redirect('password_change_done')  
            except Usuario.DoesNotExist:
                messages.error(request, 'No se encontró un usuario con ese nombre.')
    else:
        form = CustomPasswordChangeForm()

    return render(request, 'change_password.html', {'form': form})

def password_change_done_view(request):
    return render(request, 'password_change_done.html')
def logout_view(request):
    logout(request)
    messages.success(request, "Has cerrado sesión exitosamente.")
    return redirect('login') 
def view(request):
    return render(request,'home.html')

@login_required
@require_POST
def shutdown_codespace(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            codespace_name = data.get("codespace_name")
            
            if not codespace_name:
                return JsonResponse({"error": "Nombre de codespace no proporcionado."}, status=400)
            
            result = run([GH_WINDOWS_PATH, "codespace", "stop", "-c", codespace_name], check=True, capture_output=True, text=True)


            return JsonResponse({"output": f"Codespace '{codespace_name}' apagado con éxito."})

        except CalledProcessError as e:
            print(f"Error al ejecutar el comando: {e}")
            return JsonResponse({"error": f"Error al ejecutar el comando: {e.stderr}"}, status=500)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Método no permitido."}, status=405)

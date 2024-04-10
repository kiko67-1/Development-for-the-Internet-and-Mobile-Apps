from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.template import loader
from django.utils import timezone
from django.core.files.storage import FileSystemStorage
from .models import Questao, Opcao, Aluno
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse, reverse_lazy


#verificacoes auxiliades do @user_passes_test
def check_superuser(user):
    return user.is_superuser
def check_mail(user):
    return user.email.endswith('@iscte-iul.pt')

#funcoes das paginas
def index(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        User.objects.create_user(username="Francisco", email="fjlml@iscte-iul.pt", password="franciscoteste")
        User.objects.create_user(username="Antonio", email="", password="antonioteste")
        User.objects.create_user(username="Rodrigo", email="", password="rodrigoteste")
        User.objects.create_superuser(username="admin", email="", password="adminteste")

    latest_question_list = Questao.objects.order_by('-pub_data')[:5]
    context = {'latest_question_list': latest_question_list}
    return render(request, 'votacao/index.html', context)

@login_required(login_url='votacao/login')
def detalhe(request, questao_id):
    questao = get_object_or_404(Questao, pk=questao_id)
    return render(request, 'votacao/detalhe.html', {'questao': questao})
@login_required(login_url='votacao/login')
def voto(request, questao_id):
    questao = get_object_or_404(Questao, pk=questao_id)
    try:
        opcao_seleccionada = questao.opcao_set.get(pk=request.POST['opcao'])
    except (KeyError, Opcao.DoesNotExist):
        return render(request, 'votacao/detalhe.html', {'questao': questao, 'error_message': "Não escolheu uma opção"})
    else:
        if request.user.aluno.total_votos >= 2+5:
            return render(request, 'votacao/detalhe.html', {'questao': questao, 'error_message': "Limite de votos atingido"})
        opcao_seleccionada.votos += 1
        opcao_seleccionada.save()
        request.user.aluno.total_votos += 1
        request.user.aluno.save()
        return HttpResponseRedirect(reverse('votacao:resultados', args=(questao.id,)))

@user_passes_test(check_superuser, login_url=reverse_lazy('votacao:login'))
def apagar_opcao(request, questao_id):
    if request.method == 'POST':
        questao = get_object_or_404(Questao, pk=questao_id)
        opcao_id = request.POST.get('opcao_a_apagar')
        opcao = Opcao.objects.get(pk=opcao_id)
        opcao.delete()
        return render(request, 'votacao/detalhe.html', {'questao': questao})

@user_passes_test(check_superuser, login_url=reverse_lazy('votacao:login'))
def criaropcao(request, questao_id):
    if request.method == 'POST':
        questao = get_object_or_404(Questao, pk=questao_id)
        nova_opcao_texto = request.POST['nova_opcao_texto']
        questao.opcao_set.create(opcao_texto=nova_opcao_texto, votos=0)
        return render(request, 'votacao/detalhe.html', {'questao': questao})

def resultados(request, questao_id):
    questao = get_object_or_404(Questao, pk=questao_id)
    return render(request, 'votacao/resultados.html', {'questao': questao})

@user_passes_test(check_superuser, login_url=reverse_lazy('votacao:login'))
def criarquestao(request):
    if request.method == 'POST':
        nova_questao_texto = request.POST.get('questao')
        Questao.objects.create(questao_texto=nova_questao_texto, pub_data=timezone.now())
        return redirect('votacao:index')
    return render(request, 'votacao/criarquestao.html')
@user_passes_test(check_superuser, login_url=reverse_lazy('votacao:login'))
def apagar_questao(request, questao_id):
    if request.method == 'POST':
        questao = get_object_or_404(Questao, pk=questao_id)
        questao.delete()
    return redirect('votacao:index')

def loginview(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user.is_superuser is True:
            if Aluno(user=user):
                pass
            else:
                ut = Aluno(user=user)
                ut.save()
        if user is not None:
            login(request, user)
            request.session['user_id'] = user.id
            request.session['is_superuser'] = user.is_superuser
            return HttpResponseRedirect(reverse('votacao:index'))
        else:
            error_message = "Nome de usuário ou senha incorretos."
            return render(request, 'votacao/login.html', {'error_message': error_message})
    else:
        return render(request, 'votacao/login.html')
def logoutview(request):
    logout(request)
    if 'user_id' in request.session:
        del request.session['user_id']
    return HttpResponseRedirect(reverse('votacao:index'))

def registar(request):
    if request.method == 'POST':
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            curso = request.POST['curso']
            if User.objects.filter(username=username).exists():
                error_message = "Nome de usuário já está em uso. Por favor, escolha outro."
                return render(request, 'votacao/registar.html', {'error_message': error_message})
            user = User.objects.create_user(username,email,password)
            user.is_superuser = False
            ut = Aluno(user=user, curso=curso)
            ut.save()
            loginview(request)
            return HttpResponseRedirect(reverse('votacao:index'))
    else:
        error_message = "Erro ao registrar o usuário. Por favor, verifique os dados fornecidos."
        return render(request, 'votacao/registar.html', {'error_message': error_message})

def perfil(request, user):
        return render(request, 'votacao/perfil.html')

def alterar(request, user):
    username = request.POST['username']
    email = request.POST['email']
    password = request.POST['password']
    curso = request.POST['curso']
    aluno = get_object_or_404(User, username=username)
    aluno.email = email
    aluno.set_password(password)
    aluno.curso=curso
    aluno.is_superuser=user.is_superuser
    aluno.save()
    return redirect('votacao:perfil', {user:user})

@login_required(login_url='/votacao/login')
def fazer_upload(request):
    if request.method == 'POST'and request.FILES.get('myfile')is not None:
        myfile = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)
        return render(request, 'votacao/fazer_upload.html', {'uploaded_file_url': uploaded_file_url})
    return render(request, 'votacao/fazer_upload.html')






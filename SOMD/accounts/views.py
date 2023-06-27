import re
from django.shortcuts import render, redirect
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib import messages
# from .models import Profile
from django.db.models import Q
from django.contrib.auth import login as auth_login

#
#SMTP
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.utils.encoding import force_str, force_bytes

from .tokens import account_activation_token

# Create your views here.
def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(request, username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect('main:mainpage')
        else:
            login_success = False
            return render(request, 'accounts/login.html', {'login_success': login_success})
        
    elif request.method == "GET":
        login_success = True
        return render(request, 'accounts/login.html', {'login_success': login_success})

# def login(request):
#         if request.method == "POST" :
#             username = 'guest';
#             password = 'simbaton'

def logout(request):
    auth.logout(request)
    return redirect("main:start") 

def needTologin(request):
    return render(request,'accounts/needTologin.html')


def signup(request):
    if request.method == "POST":
        # 폼 데이터 추출
        name = request.POST['name']
        nickname = request.POST['nickname']
        gender = request.POST['gender']
        birth = request.POST['birth']
        year = birth[:4]
        month = birth[4:6]
        day = birth[6:]
        birth = f'{year}-{month}-{day}'
        college = request.POST['college']
        department = request.POST['department']
        email = request.POST['email']
        
        # 유효성 검사 및 오류 처리
        if not re.match(r'^[a-zA-Z0-9_-]{4,16}$', request.POST['username']):
            messages.error(request, '유효한 아이디 형식이 아닙니다.')
            return redirect('accounts:signup')

        if not re.match(r'^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', request.POST['password']):
            messages.error(request, '비밀번호는 영문자, 숫자, 특수문자(@$!%*?&)를 모두 포함하여 8자 이상 입력해야 합니다.')
            return redirect('accounts:signup')

        if request.POST['password'] != request.POST['confirm']:
            messages.error(request, '비밀번호가 일치하지 않습니다.')
            return redirect('accounts:signup')

        if User.objects.filter(Q(username=request.POST['username']) | Q(email=request.POST['email'])).exists():
            messages.error(request, '이미 사용 중인 ID 또는 이메일입니다.')
            return redirect('accounts:signup')

        try:
            # 회원 생성 및 비활성화
            user = User.objects.create_user(username=request.POST['username'], password=request.POST['password'])
            user.is_active = False
            user.save()

            # 이메일 인증 관련 데이터 생성
            current_site = get_current_site(request)
            mail_subject = "SOMDI 이메일 인증이 도착했습니다"
            message = render_to_string('accounts/activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            mail_to = request.POST["email"]

            # 이메일 전송
            email = EmailMessage(mail_subject, message, to=[mail_to])
            email.send()
            messages.success(request, '가입 인증 메일을 전송했어요!')
            return render(request, 'accounts/confirmemail.html')
            
            # 인증 완료 후의 동작
            messages.success(request, '회원 가입 성공! 이메일 인증을 완료해주세요.')
            return redirect('main:mainpage')

        except Exception as e:
            messages.error(request, '회원 가입 실패..... 😭')
    return render(request, 'accounts/signup.html')

def deleteUser(request):
    user = request.user
    user.delete()
    return redirect('main:mainpage')

#계정활성화함수.......;;토큰;;
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExsit):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        auth.login(request, user)
        return redirect("main:mainpage")
    else:
        return render(request, 'start.html', {'error' : '이메일 인증이 되지않았어요!'})
    return 
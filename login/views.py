from django.shortcuts import render
from django.shortcuts import  redirect
from  . import  models
from  . import  forms
from captcha.fields import CaptchaStore
import hashlib
# Create your views here.

def index(request):
    if not request.session.get('is_login', None):
        return redirect('/login/')
    return render(request, 'login/index.html')

def login(request):
    if request.method == "POST":
        login_form=forms.UserForm(request.POST)
        message = '请检查填写的内容！'
        if  login_form.is_valid():
            username = login_form.cleaned_data.get('username')
            password = login_form.cleaned_data.get('password')
            md5 = hashlib.md5()
            md5.update(password.encode())
            password_md5 = md5.hexdigest()
            try :
                user=models.User.objects.get(name=username)

            except:
                message='用户出走了'
                return render(request, 'login/login.html', locals())
            if(password_md5==user.password):
                request.session['is_login'] = True
                request.session['user_id'] = user.id
                request.session['user_name'] = user.name
                return redirect('/index/')
            else:
                message = '密码不正确！'
                return render(request, 'login/login.html', locals())
        else:
            # print(form_obj.errors)
            message =login_form.errors
            return render(request, 'login/login.html',locals())
    login_form = forms.UserForm()
    return render(request, 'login/login.html',locals())

def register(request):
    if request.session.get('is_login', None):
        return redirect('/index/')

    if request.method == 'POST':
        register_form = forms.RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():
            username = register_form.cleaned_data.get('username')
            password1 = register_form.cleaned_data.get('password1')
            password2 = register_form.cleaned_data.get('password2')
            email = register_form.cleaned_data.get('email')
            sex = register_form.cleaned_data.get('sex')
            md5 = hashlib.md5()
            md5.update(password1.encode())
            password_md5 = md5.hexdigest()
            if password1 != password2:
                message = '两次输入的密码不同！'
                return render(request, 'login/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:
                    message = '用户名已经存在'
                    return render(request, 'login/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:
                    message = '该邮箱已经被注册了！'
                    return render(request, 'login/register.html', locals())

                new_user = models.User()
                new_user.name = username
                new_user.password = password_md5
                new_user.email = email
                new_user.sex = sex
                new_user.save()

                return redirect('/login/')
        else:
            return render(request, 'login/register.html', locals())
    register_form = forms.RegisterForm()
    return render(request, 'login/register.html', locals())

def logout(request):
    if not request.session.get('is_login', None):
        # 如果本来就未登录，也就没有登出一说
        return redirect("/login/")
    else:
        request.session.flush()
        return render(request,'/login/')
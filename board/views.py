from django.shortcuts import render, redirect, HttpResponse
from django.http import *
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from .docerators import unauthenticated_user, allowed_users
from .models import host, check
from .utils import hosts as h
from .utils import check as c
from .utils import split

# Create your views here.


@unauthenticated_user
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect("home")
        else:
            messages.error(
                request, "User not found, you don't have one! ask your admin")
    return render(request, "login.html", {})


@login_required(login_url="signin")
def logout(request):
    auth_logout(request)
    return redirect("signin")


@login_required(login_url="signin")
def home(request):
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    return render(request, "dashboard.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def hosts(request, allowed, pk):
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    hosts = host.objects.all()
    try:
        myhost = host.objects.get(id=pk)
        connected = h.test_connectivity(
            str(myhost.hostname), str(myhost.password), str(myhost.user))
    except:
        myhost = "nohost"

    allowed = allowed
    return render(request, "hosts.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def addHost(request, allowed):
    if allowed:
        if request.method == "POST":
            hostname = request.POST.get("hostname")
            ip = request.POST.get("ip")
            hostuser = request.POST.get("hostuser")
            password = request.POST.get("password")
            description = request.POST.get("description")
            try:
                last_id = host.objects.all()[:1].get().id
            except:
                last_id = 1
            newHost = host(hostname=hostname, ip=ip, user=hostuser,
                           password=password, description=description)
            newHost.save()
            messages.success(request, "host created successfully")
            return redirect("hosts/" + str(last_id))
        else:
            return HttpResponse(status=405)
    else:
        return HttpResponse(status=405)


@login_required(login_url="signin")
@allowed_users("correcteur")
def modifyHost(request, allowed):
    if allowed:
        if request.method == "POST":
            hostid = request.POST.get("mhost")
            obj = host.objects.get(pk=hostid)
            obj.hostname = request.POST.get("hostname")
            obj.ip = request.POST.get("ip")
            obj.user = request.POST.get("hostuser")
            obj.password = request.POST.get("password")
            obj.description = request.POST.get("description")
            obj.save()
            try:
                last_id = host.objects.all()[:1].get().id
            except:
                last_id = 1
            return redirect("hosts/" + str(last_id))
        else:
            return HttpResponse(status=405)
    else:
        return HttpResponse(status=405)
    pass


@login_required(login_url="signin")
@allowed_users("correcteur")
def deleteHost(request, allowed):
    if allowed:
        if request.method == "POST":
            hostid = request.POST.get("mhost")
            obj = host.objects.get(id=hostid)
            obj.delete()
            try:
                last_id = host.objects.all()[:1].get().id
            except:
                last_id = 1
            return redirect("hosts/" + str(last_id))
        else:
            return HttpResponse(status=405)
    else:
        return HttpResponse(status=405)
    pass


@login_required(login_url="signin")
def cisChecks(request,  pk):
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    myrange = range(1, 8)
    hosts = host.objects.all()
    mychecks = check.objects.filter(checknumber=pk)
    return render(request, "cischecks.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def runCheck(request, allowed):
    if allowed:
        if request.method == "POST":
            checks = request.POST.getlist('checks')
            checks1 = request.POST.getlist('checks1')
            c.delete_inventory()
            for myhostId in checks1:
                myhost = host.objects.get(pk=int(myhostId))
                if h.test_connectivity(str(myhost.hostname), str(myhost.password), str(myhost.user)):
                    c.build_inventory(
                        myhost.hostname, myhost.password, myhost.user)
                else:
                    pass
            c.remove_log_files()
            for mycheck in checks:
                c.runcheck(mycheck, "khirou", "securityA123*", "/tmp/log7")
            try:
                last_id = host.objects.all()[:1].get().id
            except:
                last_id = 1
            return redirect("lastcheck/1")
        else:
            return HttpResponse(status=405)
    else:
        return HttpResponse(status=405)
    pass


@login_required(login_url="signin")
def lastCheck(request, pk):
    my_checks_db = split.read_log()
    myhosts = h.get_hosts_from_invenotry()
    try:
        get_check = my_checks_db[int(pk)]
    except:
        get_check = None
    checkNum = str(pk)
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    return render(request, "lastcheck.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def addCor(request, allowed):
    checks = request.POST.getlist('checks')
    checklist = ""
    for check in checks:
        checklist = str(check) + ","
    print(checklist)
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    return render(request, "checkcor.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def checkCor(request, allowed):
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    return render(request, "checkcor.html", locals())


@login_required(login_url="signin")
@allowed_users("correcteur")
def vulChecks(request):
    try:
        last_id = host.objects.all()[:1].get().id
    except:
        last_id = 1
    return render(request, "hosts.html", locals())

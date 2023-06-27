from django.urls import path
from .views import *


app_name = "accounts"
urlpatterns = [
    path("login/", login, name="login"),
    path("logout/", logout, name="logout"),
    path("signup/", signup, name="signup"),
    path('deleteUser/',deleteUser, name="deleteUser"),
    path("needTologin/",needTologin, name="needTologin"),
    path("needTologin/",needTologin, name="needTologin"),
    path('activate/<str:uidb64>/<str:token>/', activate, name="activate"),
]
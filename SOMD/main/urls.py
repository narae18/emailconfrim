from django.urls import path
from .views import *

app_name = "main"
urlpatterns = [
    path('',start,name="start"),
    path('mainpage',mainpage, name="mainpage"),
    path('board/',board,name="board"),
    path('register/',register,name="register"),
    path('somd_edit/<int:id>', somd_edit, name="somd_edit"),
    path("somd_update/<int:id>", somd_update, name="somd_update"),

    path('mysomd/',mysomd,name="mysomd"),
    path('createSOMD/',createSOMD,name="createSOMD"),
    path('mainfeed/<int:id>/',mainfeed,name="mainfeed"),
    path('fix/<int:post_id>/<int:somd_id>/', fix, name="fix"),
    
    path('mainfeed/<int:somd_id>/new/',new, name="new"),
    path('mainfeed/<int:somd_id>/createpost/',createpost,name="createpost"),
    
    path('mainfeed/viewpost/<int:post_id>/',viewpost,name="viewpost"),
    path('mainfeed/post_edit/<int:post_id>/', post_edit, name="post_edit"),
    path('mainfeed/post_update/<int:post_id>/',post_update,name="post_update"),
    path('mainfeed/post_delete/<int:post_id>/',post_delete,name="post_delete"),
    path('mainfeed/comment_update/<int:post_id>/<int:comment_id>/',comment_update,name="comment_update"),
    path('mainfeed/comment_delete/<int:post_id>/<int:comment_id>/',comment_delete,name="comment_delete"),

    path('scrap/<int:post_id>/',scrap,name="scrap"),
    path('scrap_view/',scrap_view,name="scrap_view"),

    path('like/<int:post_id>/',post_like,name="post_like"),
    path('bookmark/<int:somd_id>/',bookmark,name="bookmark"),
    path('join/<int:id>/', join, name="join"),
    path('wantTojoin/<int:id>/', wantTojoin, name= 'wantTojoin'),
    
    path('members/<int:id>/',members,name="members"),
    path('members_wantTojoin/<int:somd_id>/<int:request_id>/',members_wantTojoin,name="members_wantTojoin"),
    path('members_delete/<int:somd_id>/<int:join_user_id>/',members_delete,name="members_delete"),
    
    path('alram/',alram,name="alram"),
]

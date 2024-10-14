from django.urls import path, include
from main import views

urlpatterns = [
    path('index/', views.show_index, name='index'),
    path('start/', views.start, name='start_system'),
    path('stop/', views.stop, name='stop_system'),
    path('login/', views.show_login, name='login'),
    path('return_json/', views.return_json, name='return_json'),
    path('update_info/', views.update_info, name='update_info'),
    path('login/login_view/', views.login_view, name='login_view'),
    path('main/', views.main, name='main'),
    path('login/register_view/', views.register_view, name='register_view'),

]

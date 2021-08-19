from django.contrib import admin
from .models import *
# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("email",'full_name','is_admin','date_joined')
    list_filter = ('is_admin','is_active')
    search_fields = ("email",'full_name')


@admin.register(forgetotp)
class forgetotpAdmin(admin.ModelAdmin):
    list_display = ("user",'code','is_used','expire','attempt')


@admin.register(useraddress)
class forgetotpAdmin(admin.ModelAdmin):
    list_display = ("user",'name','city','state','zipcode','address')

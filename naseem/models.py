from django.db import models
from datetime import datetime,timedelta, timezone
import pytz
from django.db import models
from django.contrib.auth.models import AbstractUser,AbstractBaseUser,BaseUserManager
from django.db.models.fields import EmailField
# Create your models here.

class MyAccountManager(BaseUserManager):
    def create_user(self,email,password=None):
        if not email:
            raise  ValueError("Users must have an email Address")
        if len(email) > 1000:
            raise  ValueError("Email Address must not exceed the length of 1000") 
        if not password:
            raise  ValueError("Password must be something")    
        user = self.model(
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self,email,password):
        if not email:
            raise  ValueError("Users must have an email Address")
        if len(email) > 1000:
            raise  ValueError("Email Address must not exceed the length of 1000") 
        if not password:
            raise  ValueError("Password must be something")    
        user = self.create_user(
            email=self.normalize_email(email),
            password=password
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user



class User(AbstractBaseUser):
    full_name = models.CharField(verbose_name = "full_name",max_length = 1000)
    email = models.EmailField(verbose_name = "email",max_length = 1000,unique = True)
    date_joined = models.DateTimeField(verbose_name = "Date joined",auto_now_add = True)
    last_login = models.DateTimeField(verbose_name = "Date joined",auto_now = True)
    is_admin = models.BooleanField(default = False)
    is_active = models.BooleanField(default = True)
    is_staff = models.BooleanField(default = False)
    is_superuser = models.BooleanField(default = False)
    # is_valid = models.BooleanField(default=False)
    
    objects = MyAccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.email
    def has_perm(self,perm,obj = None):
        return self.is_active
    def has_module_perms(self,app_Label):
        return True    


# class email_verify(models.Model):
#     user=models.ForeignKey(User,on_delete=models.CASCADE)
#     uid=models.CharField(default="",max_length=400)
#     def __str__(self):
#         return self.user.email

class forgetotp(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    code = models.CharField(max_length=10,blank=True)
    is_used = models.BooleanField(default=False) 
    expire  = models.DateTimeField(auto_now=False, auto_now_add=False,null=True)
    attempt = models.IntegerField(default=0)
    def __str__(self):
        return self.code


class useraddress(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    name = models.CharField(default="",max_length=400)
    city = models.CharField(default="",max_length=400)
    state = models.CharField(default="",max_length=400)
    zipcode = models.CharField(default="",max_length=400)
    address = models.CharField(default="",max_length=400)
    def __str__(self):
        return self.name



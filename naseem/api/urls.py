from django.urls import path
from . import views
 
urlpatterns = [

    path("signup",views.signup.as_view()),
    path("login",views.login),
    path("sentotp",views.send_otp.as_view()),
    path('verifyotp',views.verify_otp.as_view()),
    path("add_or_get_address",views.add_or_get_address.as_view()),
    path("get_single_address",views.get_single_address.as_view()),
    path("delete_address",views.delete_address.as_view()),

]





'''
    path("signup",views.RegisterAPI.as_view()),
    path("login",views.loginapi),

    path("addapi/",views.AddAddressAPIView.as_view()),
    path("getapi/",views.GetUserAddressAPIView.as_view()),
    path("listapi/",views.GetUserAddressListAPIView.as_view()),
    
    path('profileapi',views.GetUserProfileAPIView.as_view()),
    path('emailapi',views.SendEmailAPIView.as_view()),
    path('checkapi',views.CheckOtpAPIView.as_view()),

    path("emailotp",views.EmailOtpSend.as_view()),
    path("verifyotp",views.OtpVerification.as_view()),
    
    path("add_or_get_address",add_or_get_address.as_view()),
    path("get_single_address",get_single_address.as_view()),
    path("delete_address",delete_address.as_view()),
    
   # path("sentemail",views.SendEmailAPIView.as_view()),
   # path('verify',views.CheckOtpAPIView.as_view()),
'''
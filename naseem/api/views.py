from rest_framework import serializers
from rest_framework.generics import ListAPIView, CreateAPIView, DestroyAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from .serializers import *
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.http import HttpResponse
import json
from ..models import *
import random
from datetime import datetime, timedelta


def check_blank_or_null(data):
	status=True
	for x in data:
		if x=="" or x==None:
			status=False
			break
		else:
			pass					
	return status

class signup(APIView):
    def post(self,request):
        serializer = signupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'account has been successfully'},status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)



@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
    password = request.data.get("password")
    email= request.data.get("email")
    if email is None or password is None:
        return Response({'error': 'Please provide both email and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=email, password=password)
    if not user and user.is_valid == True:
        returnMessage = {'error': 'Invalid Credentials or Your account is not verified'}
        return HttpResponse(
        json.dumps(returnMessage),
        content_type = 'application/javascript; charset=utf8'
    )
    token, _ = Token.objects.get_or_create(user=user)
    print(token)
    returnToken = {'token':token.key}
    return HttpResponse(
        json.dumps(returnToken),
        content_type = 'application/javascript; charset=utf8'
    )

class send_otp(APIView):
    def post(self,request):
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            if forgetotp.objects.filter(user=User.objects.get(email=email)).exists():
                fp=forgetotp.objects.get(user=User.objects.get(email=email))
                fp.delete()
            otp=random.randint(1000,10000)
            fp=forgetotp.objects.create(user=User.objects.get(email=email))
            fp.code=otp
            fp.expire=datetime.now()+timedelta(minutes=5)
            fp.save()
            return Response({'message':'Otp has been sent to your mail successfull'},status=HTTP_200_OK)
        return Response({'message':"Email Is not exists"}, status=HTTP_400_BAD_REQUEST)

class verify_otp(APIView):
    def post(self,request):
        email = request.data['email']
        otp = request.data['otp']
        password = request.data['password']
        if check_blank_or_null([email,otp,password]) and User.objects.filter(email=email).exists():
            otp=random.randint(1000,10000)
            user=User.objects.get(email=email)
            if forgetotp.objects.filter(code=otp,user=user,is_used=False,expire__lte=datetime.now()).exists():
                fp=forgetotp.objects.get(code=otp,user=user,is_used=False,expire__lte=datetime.now())
                fp.is_used=True
                fp.save()
                if fp.attempt > 5:
                    user=User.objects.get(email=email)
                    user.set_passwod(password)
                    user.save()
                    return Response({'message':'password has been successfully changed'},status=HTTP_200_OK)
                else:
                    return Response({'message':'All Attempt has been '},status=HTTP_400_BAD_REQUEST)
            else:
                fp=forgetotp.objects.get(user=User.objects.get(email=email))
                fp.attempt+=1
                fp.save()
                return Response({'message':'Worng otp'},status=HTTP_400_BAD_REQUEST)
        else:
            return Response({'message':"Email Is not exists"}, status=HTTP_400_BAD_REQUEST)


class add_or_get_address(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request):
        serializer=AddaddressSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'address has been successfully added'},status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def get(self,request):
        addr=useraddress.objects.filter(user=request.user)
        serializer=addressSerializer(addr,many=True)
        return Response({'data':serializer.data},status=HTTP_200_OK)



class get_single_address(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request,args,kwargs):
        pk=request.POST['pk']
        if check_blank_or_null([pk]) and useraddress.objects.filter(user=request.user,pk=pk).exists():
            addr=useraddress.objects.get(user=request.user,pk=pk)
            serializer=addressSerializer(addr,many=False)
            return Response({'data':serializer.data},status=HTTP_200_OK)
        return Response({'message':"Address Is not exists"}, status=HTTP_400_BAD_REQUEST)
    


class delete_address(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request,args,kwargs):
        pk=request.POST['pk']
        if check_blank_or_null([pk]) and useraddress.objects.filter(user=request.user,pk=pk).exists():
            addr=useraddress.objects.get(user=request.user,pk=pk)
            addr.delete()
            return Response({'data':"Address successfully delete"},status=HTTP_200_OK)
        return Response({'message':"Address Is not exists"}, status=HTTP_400_BAD_REQUEST)
    


{

"name":"osman",
"city":"hydrabaad",
"pincode":202020,
"state":"kullu",
"full_name":"Md Osman",
"email":"naa@gmail.com",
"address":"kallu manali"

}
{

"phone_number":"995657647354",
"city":"hydrabaad",
"full_name":"Md Khan",
"email":"admin@gmail.com",
"profile_image":"C:\Users\Mohd Naseem\Downloads\laptop2.jpg"


}

<!-- The core Firebase JS SDK is always required and must be listed first -->
<script src="https://www.gstatic.com/firebasejs/8.8.0/firebase-app.js"></script>

<!-- TODO: Add SDKs for Firebase products that you want to use
     https://firebase.google.com/docs/web/setup#available-libraries -->
<script src="https://www.gstatic.com/firebasejs/8.8.0/firebase-analytics.js"></script>

<script>                                                                                                                                                                              
  // Your web app's Firebase configuration
  // For Firebase JS SDK v7.20.0 and later, measurementId is optional
  var firebaseConfig = {
    apiKey: "AIzaSyBOVaM9DGt4gzKiPkPW_BU-qeAs03xqZzM",
    authDomain: "myproject-f29ed.firebaseapp.com",
    databaseURL: "https://myproject-f29ed-default-rtdb.firebaseio.com",
    projectId: "myproject-f29ed",
    storageBucket: "myproject-f29ed.appspot.com",
    messagingSenderId: "598630777243",
    appId: "1:598630777243:web:0fd9115f041d30155be13e",
    measurementId: "G-XX7QFM6YG2"
  };
  // Initialize Firebase
  firebase.initializeApp(firebaseConfig);
  firebase.analytics();
</script>







class SendEmailAPIView(APIView):
    code = CharField(allow_blank=True)

    def get_object(self):
        return self.request.user

    def post(self, request):
        user = self.get_object()
        serializer = SendEmailSerializer(data = request.data)

        if serializer.is_valid():
            email = serializer.data.get("email")
            code = serializer.data.get("code")

            send_mail(
                'OTP Verification Code from zainul',
                'your otp verification code is  ' + str(code) + ', Now, go to Otp verification page',
                'md@gmail.com',
                [email],
                fail_silently=False,
            )

            return Response({
                'message': 'Email Sent Successfully',
                'user':serializer.data.get("user_id")
            }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class CheckOtpAPIView(ListAPIView):
    code = CharField(allow_blank=True)
    user = CharField(allow_blank=True)

    def get_object(self):
        return self.request.user

    def post(self, request):
        userObj = self.get_object()
        serializer = CheckOtpSerializer(data=request.data)

        if serializer.is_valid():
            return Response({
                'message': 'Otp Verified Successfully',
            }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class GetUserProfileAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self,request,*args,**kwargs):
        user = request.user
        try:
            obj = User.objects.get(id=user.id)
        except:
            return Response({
                'success' : 'False',
                'message' : 'No user found',
            },status=HTTP_400_BAD_REQUEST)
    
        serializer = GetUserProfileDetailsSerializer(obj)
        data       = serializer.data        
        return Response({
            'success' : 'True',
            'message' : 'Data retrieved successfully',
            'data'    : data
        },status=HTTP_200_OK)



class GetUserAddressAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self,request,*args,**kwargs):
        user = request.user
        try:
            obj = useraddress.objects.get(user=user)
        except:
            return Response({
                'success' : 'False',
                'message' : 'No user found',
            },status=HTTP_400_BAD_REQUEST)

        serializer = GetUserAddressSerializer(obj)
        data       = serializer.data        
        return Response({
            'success' : 'True',
            'message' : 'Data retrieved successfully',
            'data'    : data
        },status=HTTP_200_OK)

class GetUserAddressListAPIView(ListAPIView):
    queryset = useraddress.objects.all()
    serializer_class = GetUserAddressSerializer
    authentication_classes=[BasicAuthentication]
    permission_classes=[IsAuthenticated]


class AddAddressAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request,*args,**kwargs):
        user = request.user
        data = request.data 

        try:
            obj = User.objects.get(id=user.id)
        except:
            return Response({
                'success' : 'False',
                'message' : 'Invalid user'
            },status=HTTP_400_BAD_REQUEST)    

        serializer = AddAddressSerializer(data=data,context={'request' : request})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'success' : 'True',
                'message' : 'Address added successfully'
            },status=HTTP_200_OK)
        return Response(serializer.errors,status=HTTP_404_NOT_FOUND)



class RegisterAPI(APIView):
    def post(self,request):
        serializer = signupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'account has been successfully'},status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes((AllowAny,))
def loginapi(request):
    password = request.data.get("password")
    email= request.data.get("email")
    if email is None or password is None:
        return Response({'error': 'Please provide both email and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=email, password=password)
    if not user and user.is_valid == True:
        returnMessage = {'error': 'Invalid Credentials or Your account is not verified'}
        return HttpResponse(
        json.dumps(returnMessage),
        content_type = 'application/javascript; charset=utf8'
    )
    token, _ = Token.objects.get_or_create(user=user)
    print(token)
    returnToken = {'token':token.key}
    return HttpResponse(
        json.dumps(returnToken),
        content_type = 'application/javascript; charset=utf8'
    )


class EmailOtpSend(APIView):
    def post(self,request):
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            if forgetotp.objects.filter(user=User.objects.get(email=email)).exists():
                fp=forgetotp.objects.get(user=User.objects.get(email=email))
                fp.delete()
            otp=random.randint(1000,10000)
            fp,__=forgetotp.objects.create(user=User.objects.get(email=email))
            fp.code=otp
            fp.expire=datetime.now()+timedelta(minutes=30)
            fp.save()
            return Response({'message':'Otp has been sent to your mail successfull'},status=HTTP_200_OK)
        return Response({'message':"Email Is not exists"}, status=HTTP_400_BAD_REQUEST)

class OtpVerification(APIView):
    def post(self,request):
        email = request.POST['email']
        otp = request.POST['otp']
        password = request.POST['password']
        if check_blank_or_null([email,otp,password]) and User.objects.filter(email=email).exists():
            otp=random.randint(1000,10000)
            user=User.objects.get(email=email)
            if forgetotp.objects.filter(code=otp,user=user,is_used=False,expire__lte=datetime.now()).exists():
                fp=forgetotp.objects.get(code=otp,user=user,is_used=False,expire__lte=datetime.now())
                fp.is_used=True
                fp.save()
                if fp.attempt < 5:
                    user=User.objects.get(email=email)
                    user.set_passwod(password)
                    user.save()
                    return Response({'message':'password has been successfully changed'},status=HTTP_200_OK)
                else:
                    return Response({'message':'All Attempt has been '},status=HTTP_400_BAD_REQUEST)
            else:
                fp=forgetotp.objects.get(user=User.objects.get(email=email))
                fp.attempt+=1
                fp.save()
                return Response({'message':'Worng otp'},status=HTTP_400_BAD_REQUEST)
        else:
            return Response({'message':"Email Is not exists"}, status=HTTP_400_BAD_REQUEST)



    def get(self,request):
        addr=useraddress.objects.filter(user=request.user)
        serializer=addressSerializer(addr,many=True)
        return Response({'data':serializer.data},status=HTTP_200_OK)



class get_single_address(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request,args,kwargs):
        pk=request.POST['pk']
        if check_blank_or_null([pk]) and useraddress.objects.filter(user=request.user,pk=pk).exists():
            addr=useraddress.objects.get(user=request.user,pk=pk)
            serializer=addressSerializer(addr,many=False)
            return Response({'data':serializer.data},status=HTTP_200_OK)
        return Response({'message':"Address Is not exists"}, status=HTTP_400_BAD_REQUEST)
    


class delete_address(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self,request,args,kwargs):
        pk=request.POST['pk']
        if check_blank_or_null([pk]) and useraddress.objects.filter(user=request.user,pk=pk).exists():
            addr=useraddress.objects.get(user=request.user,pk=pk)
            addr.delete()
            return Response({'data':"Address successfully delete"},status=HTTP_200_OK)
        return Response({'message':"Address Is not exists"}, status=HTTP_400_BAD_REQUEST)

def check_blank_or_null(data):
	status=True
	for x in data:
		if x=="" or x==None:
			status=False
			break
		else:
			pass					
	return status














from rest_framework.generics import (
    ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView, CreateAPIView
)
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from .serializers import *
import random
from django.core.mail import send_mail
from accounts.models import *

User = get_user_model()
from rest_framework_jwt.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class UserDetailsAPIView(RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    lookup_field = 'pk'


class UserUpdateAPIView(UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    lookup_field = 'pk'


class UserDeleteAPIView(DestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserDetailSerializer
    lookup_field = 'pk'


class UserListAPIView(ListAPIView):
    queryset = User.objects.all().order_by("id")
    serializer_class = UserListSerializer


class SendEmailAPIView(APIView):
    otp_value = CharField(allow_blank=True)

    def get_object(self):
        return self.request.user

    def post(self, request):
        user = self.get_object()
        serializer = SendEmailSerializer(data = request.data)

        if serializer.is_valid():
            email = serializer.data.get("email")
            otp_value = serializer.data.get("otp_value")

            send_mail(
                'OTP Verification Code from zainul',
                'your otp verification code is  ' + str(otp_value) + ', Now, go to Otp verification page',
                't4snietzainul@gmail.com',
                [email],
                fail_silently=False,
            )

            return Response({
                'message': 'Email Sent Successfully',
                'user':serializer.data.get("user_id")
            }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class CheckOtpAPIView(ListAPIView):
    otp_value = CharField(allow_blank=True)
    user = CharField(allow_blank=True)

    def get_object(self):
        return self.request.user

    def post(self, request):
        userObj = self.get_object()
        serializer = CheckOtpSerializer(data=request.data)

        if serializer.is_valid():
            return Response({
                'message': 'Otp Verified Successfully',
            }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class ResetPasswordAPIView(APIView):
    new_password = CharField(allow_blank=True)
    conf_password = CharField(allow_blank=True)
    user_id = CharField(allow_blank=True)

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.data.get("new_password")
            user_id = serializer.data.get('user_id')

            u = User.objects.get(id__exact=user_id)
            u.set_password(new_password)
            u.save()
            return Response(
                {
                    'message': 'Your password changed successfully'
                }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class ChangePasswordAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.data.get("old_password")
            new_password = serializer.data.get("new_password")
            conf_password = serializer.data.get("confPassword")

            if not user.check_password(old_password):
                return Response({
                    "message": "You entered wrong current password"},
                    status=400)

            user.set_password(new_password)
            user.save()
            return Response(
                {
                    'message': 'Your password changed successfully'
                }, status=200)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class ProfileApiView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]

    def get(self, request, *args, **kwargs):
        user = request.user
        data = UserDetailSerializer(user).data
        return Response({
            'response': data
        }, 200)

    def post(self, request, *args, **kwargs):
        data = request.data
        user = request.user
        serializer = UpdateProfileSerializer(data=data, instance=user)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'data':serializer.data,
                'message': 'User details saved succesfully'
            }, status=HTTP_200_OK)

        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class UserCreateAPIView(CreateAPIView):
    serializer_class = UserCreateSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data':serializer.data,'message':'registered successfully'},status=HTTP_200_OK)
        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)


class UserLoginAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid():
            return Response({
                'message': 'Login successfully',
                'data': serializer.data
            }, status=200)
        error_keys = list(serializer.errors.keys())
        if error_keys:
            error_msg = serializer.errors[error_keys[0]]
            return Response({'message': error_msg[0]}, status=400)
        return Response(serializer.errors, status=400)

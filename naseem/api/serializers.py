from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models import fields
from django.db.models.base import Model
from rest_framework.fields import EmailField
from rest_framework.serializers import ModelSerializer, Serializer, CharField, ImageField, SerializerMethodField,EmailField
from ..models import User, useraddress
import re
from django.utils.crypto import get_random_string
from django.core.mail import send_mail

def check_email(email):
    regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
    if(re.search(regex, email)):
        return True
    else:
        return False

class signupSerializer(Serializer):
    full_name = CharField(error_messages={'required':'Full name is required', 'blank':'Full name is required'},max_length=400)
    email = EmailField(error_messages={'required':'Eamil is required', 'blank':'Email is required'},max_length=400)
    password=CharField(error_messages={'required':'Eamil is required', 'blank':'Email is required'})
    def validate(self, data):
        email = data.get('email')
        password = data.get("password")
        if check_email(email) and User.objects.filter(email=email).exists():
            raise ValidationError('Email is not valid.Please enter valid Email')
        print(password)
        print(email)    
        if password.isalpha() == True:
            raise ValidationError('Password must be alpha numeric')
        return data
    def create(self, validated_data):
        full_name = self.validated_data['full_name']
        email = self.validated_data['email']
        password = self.validated_data['password']
        user=User.objects.create_user(email=email,password=password)
        user.full_name=full_name
        user.set_password(password)
        user.save()
        return validated_data

class  AddaddressSerializer(Serializer):
    addressname = CharField(error_messages={'required':'addressname is required', 'blank':'addressname is required'},max_length=400)
    city = CharField(error_messages={'required':'city is required', 'blank':'city is required'},max_length=400)
    state = CharField(error_messages={'required':'state is required', 'blank':'state is required'},max_length=400)
    zipcode = CharField(error_messages={'required':'zipcode is required', 'blank':'zipcode is required'},max_length=400)
    address = CharField(error_messages={'required':'address is required', 'blank':'address is required'},max_length=400)
    def validate(self, data):
        if data.get("addressname") == "":
            raise ValidationError("Address name can not be empty")
        if data.get("city") == "":
            raise ValidationError("city can not be empty")
        if data.get("state") == "":
            raise ValidationError("state can not be empty")
        if data.get("zipcode") == "":
            raise ValidationError("zipcode can not be empty")
        if data.get("address") == "":
            raise ValidationError("address can not be empty")            
        return data
    def create(self, validated_data):
        adrs=useraddress.objects.get_or_create(user=request.user,name=self.validated_data['addressname'])
        adrs.city=self.validated_data['city']
        adrs.state=self.validated_data['state']
        adrs.zipcode=self.validated_data['zipcode']
        adrs.address=self.validated_data['address']
        adrs.save()
        return validated_data       

class addressSerializer(Serializer):
    class Mete:
        model = useraddress
        fields = ['id','name','city','state','zipcode','address']       





























'''
class SendEmailSerializer(Serializer):
    email = EmailField(label='Email Address', error_messages={'required': 'email field key is required', 'blank': 'email field is required'})
    code = CharField(read_only=True)
    user_id = CharField(allow_blank=True, read_only=True)

    def validate(self, data):
        email = data['email']

        if email:
            user = User.objects.filter(email__iexact=email, account_type='1').exclude(
                email__isnull=True, ).exclude(email__iexact='').distinct()
            if user.exists() and user.count() == 1:
                # user_obj = user.first().id
                userObj =user.first()

                code = random.randint(1, 9999)
                data['code'] = code
                qs = forgetotp.objects.filter(user=userObj)
                if qs.exists():
                    obj = qs.first()
                    obj.code = code
                    obj.save()
                else:
                    created = forgetotp.objects.create(user= userObj, code=code)

            else:
                raise APIException({
                    'message': 'User with this email not exist',
                })
        else:
            raise APIException({
                'message' : 'Invalid Input'
            })
        data['code'] = code
        data['user_id'] = user.first().id
        return data


class CheckOtpSerializer(Serializer):
    code = CharField(error_messages={'required':'otp value key is required', 'blank':'otp value is required'})
    #user = CharField(error_messages={'required':'user key is required', 'blank':'otp value is required'})

    def validate(self, data):
        code = data['code']
        user=request.user
        #user = data['user']

        if len(code) < 4:
            raise ValidationError("otp length should be 4")

        qs = forgetotp.objects.filter(user=user).distinct()

        if qs.exists():
            otp = qs.first().code
        else:
            raise ValidationError("user is not valid")

        if code == otp:
            print('correct otp')
        else:
            raise ValidationError("Incorrect otp please try again")

        return data



class GetUserProfileDetailsSerializer(ModelSerializer):
    class Meta:
        model  = User
        fields=['email','first_name','last_name']
        


class GetUserAddressSerializer(ModelSerializer):
    class Meta:
        model  = useraddress
        fields = ['user_id','country','city','pincode','street','house_number']


class signupSerializer(Serializer):
    first_name = CharField(error_messages={'required':'first name is required', 'blank':'first name is required'},max_length=400)
    last_name = CharField(error_messages={'required':'last name is required', 'blank':'last name is required'},max_length=400)
    email = EmailField(error_messages={'required':'Eamil is required', 'blank':'Email is required'},max_length=400)
    password=CharField(error_messages={'required':'Eamil is required', 'blank':'Email is required'})
    def validate(self, data):
        email = data.get('email')
        password = data.get("password")
        if check_email(email) and User.objects.filter(email=email).exists():
            raise ValidationError('Email is not valid.Please enter valid Email')
        print(password)
        print(email)    
        if password.isalpha() == True:
            raise ValidationError('Password must be alpha numeric')
        return data
    def create(self, validated_data):
        first_name = self.validated_data['first_name']
        last_name=self.validated_data['last_name']
        email = self.validated_data['email']
        password = self.validated_data['password']
        user=User.objects.create_user(email=email,password=password)
        user.first_name=first_name
        user.last_name=last_name
        user.set_password(password)
        user.save()
        return validated_data

class AddAddressSerializer(ModelSerializer):
    country      = serializers.CharField(allow_blank=True)
    city         = serializers.CharField(allow_blank=True)
    pincode      = serializers.CharField(allow_blank=True)
    street       = serializers.CharField(allow_blank=True)
    house_number = serializers.CharField(allow_blank=True)

    class Meta:
        model  = useraddress
        fields = ['country','city','pincode','street','house_number']


    def validate(self,data):
        country      = data['country']
        city         = data['city']
        pincode      = data['pincode']
        street       = data['street']
        house_number = data['house_number']


        if not country or country == '':
            raise APIException({
        'success' : 'False',
        'message' : 'country is required'
        })

        if not city or city == '':
            raise APIException({
        'success' : 'False',
        'message' : 'city is required'
        })
        
        if not pincode or pincode == '':
            raise APIException({
        'success' : 'False',
        'message' : 'pincode is required'
        })
        
        if not street or street == '':
            raise APIException({
        'success' : 'False',
        'message' : 'street is required'
        })
        
        if not house_number or house_number == '':
            raise APIException({
        'success' : 'False',
        'message' : 'please provide house/office/building number'
        })

        return data 

    def create(self,validated_data):
        country      = validated_data['country']
        city         = validated_data['city']
        pincode      = validated_data['pincode']
        street       = validated_data['street']
        house_number = validated_data['house_number']

        user=self.context['request'].user
        otherUser=useraddress.objects.filter(user=user).first()
        if not otherUser:
            raise APIException({
        'success' : 'False',
        'message' : 'This user is not registerd'
        })

        otherUser.country      = country
        otherUser.city         = city
        otherUser.pincode      = pincode
        otherUser.street       = street
        otherUser.house_number = house_number 
        otherUser.save()

        return validated_data

    
class addressSerializer(Serializer):
    class Mete:
        model = useraddress
        fields = ['id','name','city','state','zipcode','address'] 


def check_email(email):
    regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
    if(re.search(regex, email)):
        return True
    else:
        return False

'''
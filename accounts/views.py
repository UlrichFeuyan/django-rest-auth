from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from accounts.utils import send_code_to_user
from .serializers import LoginSerializer, UserRegisterSerializer, PasswordResetRequestSerializer, SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
from .models import OneTimePassword, User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import IsAuthenticated


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    
    
    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            full_name = str(user["first_name"]) + ' ' + str(user["last_name"])
            
            # Send email function user['email']
            send_code_to_user(user['email'])
            
            return Response(
                {
                    'data': user,
                    'message': f'Hi {full_name}, thanks for signing up. A passcode has been send on your email.'
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    def post(self, request):
        otpcode = request.data.get('otp')
        try:
            user_code_obj = OneTimePassword.objects.get(code=otpcode)
            user = user_code_obj.user
            if not user.is_verified:
                user.is_verified=True
                user.save()
                return Response(
                    {
                        'message': 'Account email verified successfully'
                    },
                    status=status.HTTP_200_OK
                )
            return Response(
                {
                    'message': 'Code is invalid. User already verified'
                },
                status=status.HTTP_204_NO_CONTENT
            )
        except OneTimePassword.DoesNotExist:
            return Response(
                {
                    'message': 'Password not provided'
                },
                status=status.HTTP_404_NOT_FOUND
            )


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        data={
            'msg': 'Ist works !'
        }
        return Response(data, status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message': "A link has been sent to you email to reset your password."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'Token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials is valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message': 'Token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'password reset successfull'}, status=status.HTTP_200_OK)

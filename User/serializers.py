from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.db.models import Q
# from rest_framework import serializers


from rest_framework.serializers import (
    CharField,
    EmailField,
    HyperlinkedIdentityField,
    ModelSerializer,
    SerializerMethodField,
    ValidationError
)

User = get_user_model()  # built in user model


class UserDetailSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'first_name',
            'last_name',
        ]


class UserCreateSerializer(ModelSerializer):
    email = EmailField(label='Email')
    email2 = EmailField(label='Confirm Email')
    password = CharField(style={'input_type': 'password'}, write_only=True)
    c_password = CharField(label="Confirm Password", style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'email2',
            'password',
            'c_password',

        ]
        extra_kwargs = {"password": {"write_only": True}, "c_password": {"write_only": True}}

    def validate(self, data):
        # email = data['email']
        # user_qs = User.objects.filter(email=email)
        # if user_qs.exists():
        #     raise ValidationError("This user has already registered.")
        return data

    def validate_email(self, value):
        data = self.get_initial()  # give the initial data that is passed
        email1 = data.get("email2")
        email2 = value
        if email1 != email2:
            raise ValidationError("Emails must match.")

        user_qs = User.objects.filter(email=email1)
        if user_qs.exists():
            raise ValidationError("This user has already registered.")

        return value

    def validate_email2(self, value):
        data = self.get_initial()
        email1 = data.get("email")
        email2 = value
        if email1 != email2:
            raise ValidationError("Emails must match.")
        return value

    def validate_c_password(self, value):
        data = self.get_initial()
        password = data.get("password")
        c_password = value
        if password != c_password:
            raise ValidationError("Password do not match.")
        return value

    def create(self, validated_data):
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        user_obj = User(
            username=username,
            email=email
        )
        user_obj.set_password(password)
        user_obj.save()
        return validated_data


class UserLoginSerializer(ModelSerializer):
    token = CharField(allow_blank=True, read_only=True)
    # username_email = CharField(label="Username or Email", required=False, allow_blank=True)
    email = EmailField(label='Email Address', required=False, allow_blank=True)
    password = CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = [
            #'username_email',
             'email',
            'password',
            'token',

        ]
        extra_kwargs = {"password":
                            {"write_only": True}
                        }

    def validate(self, data):
        user_obj = None
        email = data.get("email", None)
        # username = data.get("username", None)
        # username_email = data.get("username", "email")
        password = data["password"]
        if not email:
            raise ValidationError("An email is required.")
        user = User.objects.filter(
            # Q(username_email=username_email)
            Q(email=email)  # needs to be only one of them
        ).distinct()
        user = user.exclude(email__isnull=True).exclude(
            email__iexact='')  # takes those whose email/username field isn't null
        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise ValidationError("This email is not valid.")

        if user_obj:
            if not user_obj.check_password(password):
                raise ValidationError("Incorrect credentials. Try again.")
            data["token"] = "Random token"
            # email = data['email']
        # user_qs = User.objects.filter(email=email)
        # if user_qs.exists():
        #     raise ValidationError("This user has already registered.")
        return data
from django.db.models.signals import post_save
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
from django.dispatch import receiver
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, UserDevice

@receiver(post_save, sender=CustomUser)
def send_verification_email(sender, instance, created, **kwargs):
    if created:
        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(instance)
        uid = instance.pk
        verification_link = reverse('accounts:verify-email', kwargs={'uidb64': uid, 'token': token})
        verification_url = f"{settings.SITE_URL}{verification_link}"

        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {verification_url}',
            settings.DEFAULT_FROM_EMAIL,
            [instance.email],
        )


@receiver(user_logged_in)
def on_user_login(sender, request, user, **kwargs):
    user_agent = parse(request.META['HTTP_USER_AGENT'])
    device_name = user_agent.device.family
    browser = user_agent.browser.family
    operating_system = user_agent.os.family
    ip_address = request.META.get('REMOTE_ADDR')

    UserDevice.objects.create(
        user=user,
        device_name=device_name,
        device_type='Mobile' if user_agent.is_mobile else 'PC',
        browser=browser,
        operating_system=operating_system,
        ip_address=ip_address,
        login_time=timezone.now()
    )

@receiver(user_logged_out)
def on_user_logout(sender, request, user, **kwargs):
    user_devices = UserDevice.objects.filter(user=user, ip_address=request.META.get('REMOTE_ADDR'))
    if user_devices.exists():
        user_device = user_devices.first()
        user_device.last_active = timezone.now()
        user_device.save()
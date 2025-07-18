from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block a specific IP address'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='The IP address to block')

    def handle(self, *args, **kwargs):
        ip = kwargs['ip_address']
        try:
            blocked, created = BlockedIP.objects.get_or_create(ip_address=ip)
            if created:
                self.stdout.write(self.style.SUCCESS(f'Successfully blocked IP: {ip}'))
            else:
                self.stdout.write(f'IP {ip} is already blocked.')
        except Exception as e:
            raise CommandError(f'Error blocking IP: {str(e)}')

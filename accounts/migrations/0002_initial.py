# Generated by Django 5.1.1 on 2024-09-15 16:54

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('accounts', '0001_initial'),
        ('company', '0001_initial'),
        ('employee', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='company',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='projects', to='company.company'),
        ),
        migrations.AddField(
            model_name='project',
            name='manager',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='managed_projects', to='employee.employee'),
        ),
    ]

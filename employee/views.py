from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from .models import Employee, EmployeePerformance
from .serializers import EmployeeSerializer, EmployeePerformanceSerializer

class EmployeeViewSet(viewsets.ModelViewSet):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def count(self, request):
        employee_count = self.queryset.count()
        return Response({'count': employee_count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def trends(self, request):
        # Fake data for now
        fake_labels = ['January', 'February', 'March', 'April', 'May', 'June']
        fake_values = [30, 40, 45, 60, 65, 80]
        return Response({'labels': fake_labels, 'values': fake_values}, status=status.HTTP_200_OK)


class EmployeePerformanceViewSet(viewsets.ModelViewSet):
    serializer_class = EmployeePerformanceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        employee_id = self.kwargs['employee_id']
        return EmployeePerformance.objects.filter(employee_id=employee_id)

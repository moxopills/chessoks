"""페이지네이션 설정"""

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class LeaderboardPagination(PageNumberPagination):
    """랭킹 보드 페이지네이션 (20명씩)"""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data, my_rank=None):
        """내 랭킹 정보를 포함한 응답"""
        response_data = {
            "count": self.page.paginator.count,
            "total_pages": self.page.paginator.num_pages,
            "current_page": self.page.number,
            "next": self.get_next_link(),
            "previous": self.get_previous_link(),
            "results": data,
        }
        if my_rank is not None:
            response_data["my_rank"] = my_rank
        return Response(response_data)

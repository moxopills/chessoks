from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.community.serializers import (
    BoardCategorySerializer,
    BoardCommentCreateSerializer,
    BoardCommentPageSerializer,
    BoardCommentSerializer,
    BoardPostCreateSerializer,
    BoardPostSerializer,
    BoardPostSummarySerializer,
    BoardReportCreateSerializer,
)
from apps.community.services import BoardService
from apps.core.request import parse_bool_query


class BoardCategoryListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        categories = BoardService.list_categories()
        no_count = parse_bool_query(request.query_params.get("no_count"))
        results = BoardCategorySerializer(categories, many=True).data
        return Response(
            {
                "count": len(results) if no_count else categories.count(),
                "results": results,
            }
        )


class BoardListCreateView(APIView):
    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request):
        category_code = request.query_params.get("category")
        mine_only = request.query_params.get("mine") == "1"
        no_count = parse_bool_query(request.query_params.get("no_count"))
        try:
            limit = int(request.query_params.get("limit", "0") or 0)
        except ValueError:
            limit = 0
        limit = max(0, min(limit, 20))
        posts = BoardService.list_posts(
            category_code=category_code,
            limit=limit or None,
            author=(
                request.user
                if mine_only and getattr(request.user, "is_authenticated", False)
                else None
            ),
        )
        if limit:
            results = list(posts)
            count = len(results)
        else:
            results = posts
            count = 0 if no_count else posts.count()
        serialized = BoardPostSummarySerializer(results, many=True).data
        return Response(
            {
                "count": len(serialized) if no_count else count,
                "results": serialized,
            }
        )

    def post(self, request):
        serializer = BoardPostCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        post = BoardService.create_post(
            request.user,
            category_code=data["category_code"],
            title=data["title"],
            content=data["content"],
            extra=data,
        )
        post = BoardService.get_post(post.id, viewer=request.user)
        return Response(BoardPostSerializer(post, context={"request": request}).data, status=201)


class BoardDetailView(APIView):
    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request, post_id: int):
        increment_view = request.query_params.get("no_view") != "1"
        post = BoardService.get_post(post_id, increment_view=increment_view, viewer=request.user)
        return Response(BoardPostSerializer(post, context={"request": request}).data)

    def delete(self, request, post_id: int):
        BoardService.delete_post(request.user, post_id=post_id)
        return Response(status=204)


class BoardCommentCreateView(APIView):
    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request, post_id: int):
        try:
            limit = int(request.query_params.get("limit", "0") or 0)
        except ValueError:
            limit = 0
        try:
            before_id = int(request.query_params.get("before_id", "0") or 0)
        except ValueError:
            before_id = 0

        comments, has_more, next_before_id = BoardService.list_comments(
            post_id,
            viewer=request.user,
            limit=limit or None,
            before_id=before_id or None,
        )
        payload = {
            "has_more": has_more,
            "next_before_id": next_before_id,
            "results": BoardCommentSerializer(
                comments,
                many=True,
                context={"request": request},
            ).data,
        }
        return Response(BoardCommentPageSerializer(payload).data)

    def post(self, request, post_id: int):
        serializer = BoardCommentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = BoardService.create_comment(
            request.user,
            post_id,
            content=serializer.validated_data["content"],
        )
        return Response(
            BoardCommentSerializer(comment, context={"request": request}).data,
            status=201,
        )


class BoardCommentLikeToggleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id: int):
        comment, liked = BoardService.toggle_comment_like(request.user, comment_id=comment_id)
        return Response(
            {
                "comment_id": comment.id,
                "liked": liked,
                "like_count": comment.like_count,
            }
        )


class BoardCommentDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, comment_id: int):
        BoardService.delete_comment(request.user, comment_id=comment_id)
        return Response(status=204)


class BoardReportCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = BoardReportCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        report = BoardService.create_report(request.user, **serializer.validated_data)
        return Response({"id": report.id, "status": report.status}, status=201)

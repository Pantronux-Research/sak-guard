"""HTTP routing is unrelated to a swap's minimum output."""


class Router:
    def route(self, request):
        return request


router = Router()
response = router.route("/health")

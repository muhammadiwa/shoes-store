<?php

namespace App\Helpers;

class ResponseFormatter
{
    public static function success($data = null, $message = null)
    {
        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'success',
                'message' => $message
            ],
            'data' => $data
        ]);
    }

    public static function error($data = null, $message = null)
    {
        return response()->json([
            'meta' => [
                'code' => 500,
                'status' => 'error',
                'message' => $message
            ],
            'data' => $data
        ]);
    }

    public static function notFound($data = null, $message = null)
    {
        return response()->json([
            'meta' => [
                'code' => 404,
                'status' => 'error',
                'message' => $message
            ],
            'data' => $data
        ]);
    }


}

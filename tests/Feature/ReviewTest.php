<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Models\Review;
use App\Models\User;
use Illuminate\Foundation\Testing\WithFaker;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;

use function PHPUnit\Framework\assertJson;

class ReviewTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_list_all_resto()
    {
        $count = 5;
        Review::factory()->count($count)->create();

        $user = User::factory()->createOne();
        Sanctum::actingAs($user);

        $this->getJson(route('reviews.index'))
        ->assertOk()
        ->assertJsonCount($count);
    }

    public function test_user_can_create_resto()
    {
        $data = Review::factory()->makeOne()->toArray();

        $user = User::factory()->createOne();
        Sanctum::actingAs($user);

        $this->postJson(route('reviews.store'), $data)
        ->assertCreated()
        ->assertJsonStructure(array_keys($data));
    }

    public function test_user_can_show_resto()
    {
        $data = Review::factory()->createOne();

        $user = User::factory()->createOne();
        Sanctum::actingAs($user);

        $this->getJson(route('reviews.show', $data))
        ->assertOk()
        ->assertJsonStructure(array_keys($data->toArray()));
    }

    public function test_user_can_edit_resto()
    {
        $UpdatedData = Review::factory()->makeOne()->toArray();
        $data = Review::factory()->createOne();
        
        $user = User::factory()->createOne();
        Sanctum::actingAs($user);

        $this->patchJson(route('reviews.update', $data), $UpdatedData)
        ->assertOk()
        ->assertJsonStructure(array_keys($UpdatedData));
    }

    public function test_user_can_delete_resto()
    {
        $data = Review::factory()->createOne();

        $user = User::factory()->createOne();
        Sanctum::actingAs($user);

        $this->deleteJson(route('reviews.destroy', $data))
        ->assertOk()
        ->assertJsonStructure(array_keys($data->toArray()));
    }
}
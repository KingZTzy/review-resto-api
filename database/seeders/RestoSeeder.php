<?php

namespace Database\Seeders;

use App\Models\Resto;
use App\Models\Review;
use Illuminate\Database\Seeder;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;

class RestoSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        Resto::factory()->has(Review::factory()->count(5))->count(100)->create();
    }
}

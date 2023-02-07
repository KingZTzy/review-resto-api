<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        if (config('app.debug', false)) {
            User::create(['name' => 'tester', 'email' => 'someone@email.com', 'password' => bcrypt('password')]);
        }
    }
}

package com.linkin.lklinker;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.linkin.lklinker.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'lklinker' library on application startup.
    static {
        System.loadLibrary("lklinker");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());

        Button button = binding.button;

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                lk_load();
            }
        });

    }


    /**
     * A native method that is implemented by the 'lklinker' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native void lk_load();
}
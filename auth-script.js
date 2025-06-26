// auth-script.js

document.addEventListener('DOMContentLoaded', function() {

    // IMPORTANTE: Substitua pela URL real do seu backend na Vercel!
    const apiUrl = 'https://aihugg-backend-git-main-edson-fagundes-projects.vercel.app'; 

    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');

    // --- Lógica de LOGIN ---
    if (loginForm) {
        loginForm.addEventListener('submit', async function(e) {
            e.preventDefault(); // Impede o envio padrão do formulário
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const messageDiv = document.getElementById('login-message');
            const submitButton = this.querySelector('button[type="submit"]');

            messageDiv.textContent = '';
            submitButton.disabled = true;
            submitButton.textContent = 'A verificar...';

            try {
                const response = await fetch(`${apiUrl}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, password: password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.erro || 'Erro desconhecido');
                }
                
                // SUCESSO! Guarda o token e redireciona
                localStorage.setItem('aihugg_token', data.access_token);
                messageDiv.textContent = 'Login bem-sucedido! A redirecionar...';
                messageDiv.className = 'auth-message success';
                
                // Redireciona para o dashboard após um pequeno atraso
                setTimeout(() => {
                    window.location.href = '/dashboard'; // Mude para a sua página de dashboard/planos
                }, 1500);

            } catch (error) {
                messageDiv.textContent = error.message;
                messageDiv.className = 'auth-message error';
                submitButton.disabled = false;
                submitButton.textContent = 'Entrar';
            }
        });
    }

    // --- Lógica de REGISTO ---
    if (registerForm) {
        registerForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const messageDiv = document.getElementById('register-message');
            const submitButton = this.querySelector('button[type="submit"]');

            messageDiv.textContent = '';
            submitButton.disabled = true;
            submitButton.textContent = 'A registar...';

            try {
                const response = await fetch(`${apiUrl}/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, password: password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.erro || 'Erro desconhecido');
                }

                // SUCESSO! Informa e redireciona para o login
                messageDiv.textContent = data.message;
                messageDiv.className = 'auth-message success';
                
                setTimeout(() => {
                    window.location.href = '/login'; // Redireciona para a página de login
                }, 2000);

            } catch (error) {
                messageDiv.textContent = error.message;
                messageDiv.className = 'auth-message error';
                submitButton.disabled = false;
                submitButton.textContent = 'Criar Conta';
            }
        });
    }
});
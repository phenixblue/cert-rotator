/*
Copyright © 2021 The WebRoot, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	apiv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/spf13/viper"
	"k8s.io/client-go/util/homedir"
)

var (
	cfgFile    string
	kubeconfig string
	namespace  string
	secretName string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cert-rotator",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		if kubeconfig == "" {

			if home := homedir.HomeDir(); home != "" {
				kubeconfig = filepath.Join(home, ".kube", "config")

			}
		}

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}

		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			panic(err)
		}

		secretClient := client.CoreV1().Secrets(namespace)

		targetSecret := apiv1.Secret{}
		targetSecret.Name = secretName

		secret, err := secretClient.Get(context.TODO(), targetSecret.Name, metav1.GetOptions{})

		if err != nil {
			if apierrors.IsNotFound(err) {
				fmt.Printf("Secret %q not found in %q namespace\n", targetSecret.Name, namespace)
				os.Exit(1)
			}

			fmt.Printf("An error occurred while trying to get %q secret from %q namespace: \n%v\n", targetSecret.Name, namespace, err)
		}

		fmt.Printf("Found the %q secret in the %q namespace\n", targetSecret.Name, namespace)
		//fmt.Printf("Cert:\n%v\n", string(secret.Data["tls.crt"]))
		//fmt.Printf("Key:\n%v\n", string(secret.Data["tls.key"]))

		pemBlock, _ := pem.Decode(secret.Data["tls.crt"])
		if pemBlock == nil {
			fmt.Println("Failed to decode PEM block from certificate")
		}

		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			fmt.Println("Parsing certificate data from secret failed:\n%u\n", err)
			os.Exit(1)
		}

		expireDate := cert.NotAfter

		fmt.Printf("Cert expiration: %v\n", expireDate)

		currentDatetime := time.Now()
		expiredDays := expireDate.Sub(currentDatetime).Hours() / 24

		fmt.Printf("Days until cert expires: %v\n", int(expiredDays))

		if int(expiredDays) <= 60 {
			if int(expiredDays) <= 30 {
				fmt.Println("!!! Certificate is expiring within 60 days !!!")
				rotateCert()
			}
			sendAlert()

		} else {
			fmt.Println("Certificate is not expiring within 60 days")
		}

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cert-rotator.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file)")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "namespace (default is default)")
	rootCmd.PersistentFlags().StringVarP(&secretName, "secret-name", "s", "", "name of secret resource")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home := homedir.HomeDir()
		if home == "" {
			fmt.Println("Home directory not found")
			os.Exit(1)
		}

		// Search config in home directory with name ".cert-rotator" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".cert-rotator")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func sendAlert() {
	fmt.Println("Eventually this will send an alert")
}

func rotateCert() {
	fmt.Println("eventually this will rotate the certificate and update the secret")
}

import java.awt.BorderLayout;
import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Desktop;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.Image;
import javax.swing.SwingConstants;
import javax.swing.JButton;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BoxLayout;
import javax.swing.JTextPane;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.Key;
import java.util.Base64;
import java.awt.event.ActionEvent;
import javax.swing.JToggleButton;
import javax.swing.JTextArea;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.AbstractListModel;
import javax.swing.border.LineBorder;
import javax.swing.ListSelectionModel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;

public class MainGUI extends JFrame {
	public JPanel contentPane;
	public JPanel mainMenu;
	public JPanel menuPanel;
	public JPanel TextEncryptOptions;
	public JPanel pictureEncryptOption;
	public JPanel caesarPanel;
	public JPanel aesDisplay;
	public JPanel vigenereCipher;
	private JTextField plainTextField;
	private JTextField cypherTextField;
	private JLabel errorMessage;
	private static final String algorithm = "AES";//AES is the algorithm name(it is a reserved name)
	private byte[] keyValue;
	private JTextField aesplainField;
	private JTextField plainVigenere;
	private JTextField keyVigenere;
	private JTextField cipherVigenere;
	private JTextField displayPathofFile;


	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainGUI frame = new MainGUI();
					frame.setResizable(false);
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	public MainGUI(String key){
		keyValue = key.getBytes();//string key is converted into bytes and stored in keyValue(This is for AES)
	}
	
	//////////////////////////METHODS//////////////////////////////////////
	private void checkForSpecialCharacters(String s) throws Exception{//method checks ascii if ascii value is between 32 and 126
		for(int i = 0; i<s.length(); i++){
			if(s.charAt(i) < 32 || s.charAt(i) > 126){//throws exception if a special character in added
				throw new Exception();
			}
		}	
	}
	private static String caesarShift(String plainText, int shift){
	    String s = "";
	    for(int x = 0; x < plainText.length(); x++){//loop through each character in the string
	        char c = (char)(plainText.charAt(x) + shift);//Add shift to the character and if it falls off the end of 
	        											//the alphabet then subtract shift from the number of letters in the alphabet
	        if (c > 'z')
	            s += (char)(plainText.charAt(x) - (26-shift));
	        else
	            s += (char)(plainText.charAt(x) + shift);//Add shift to the character and if it falls off the end of the alphabet then subtract shift from the number of letters in the alphabet
	    }
	    return s;//return shifted string
	}
	
	private Key generateKey() throws Exception{//method which generates AES key
		Key key = new SecretKeySpec(keyValue, algorithm);//creates secret key from byte array
		return key;
	}
	public String encrypt(String data)throws Exception{
		Key key = generateKey();//invoke generateKey and store key value in a variable
		Cipher c = Cipher.getInstance(algorithm);//class cipher is superclass of all encryption classes
		c.init(Cipher.ENCRYPT_MODE, key);//initialize cipher to encryption mode using generated key
		byte[] encryptedValues = c.doFinal(data.getBytes()); //encrypts data and stores in byte array
		String encryptedString = Base64.getEncoder().encodeToString(encryptedValues);//encodes byte array into string values	
		return encryptedString;	
	}
	
	
	public String decrypt(String encryptedData) throws Exception{
		Key key = generateKey();//invoke generateKey and store key value in a variable
		Cipher c = Cipher.getInstance(algorithm);//class cipher is superclass of all encryption classes
		c.init(Cipher.DECRYPT_MODE, key);//initialize cipher to encryption mode using generated key
		byte[] decoderVal = Base64.getDecoder().decode(encryptedData);
		byte[] val = c.doFinal(decoderVal);
		String decryptedString = new String(decoderVal);
		return decryptedString;
		}
	
	
	public static void openWebpage(String urlString) {//method opens takes URL string, and opens it on the web browser
	    try {
	        Desktop.getDesktop().browse(new URL(urlString).toURI());
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
	
	public static String vigenereEncrypt(String plainTxt, String k){	
		char cipher = ' ';
		String s =  " ";
		int plainValue, cipherValue;//will hold ascii values of plain char and encrypted char
		int kLength = k.length();//length of key
		plainTxt = plainTxt.toUpperCase();//upper case everything
		k = k.toUpperCase();
		for(int i = 0; i<plainTxt.length(); i++){
			plainValue = plainTxt.charAt(i);
			if(plainValue>65 || plainValue< 132){//ascii values from 65 -> 132 represent all uppercase alphabet letters
				cipherValue = (((int)plainTxt.charAt(i))-65+((int)k.charAt(i%kLength)-65))%26+65;//add ascii value of plaintext to the ascii value of the key
				//if index is larger than length of key, mod it to get it back to length of key then mod everything by 26(number of letters in the alphabet) to get proper values. 
				cipher = (char)cipherValue;//cast integer ascii to char and return it
				s += String.valueOf(cipher);
		}
			else{
				System.out.println("Enter proper values please");}	
			}
		return s;
	}
	
	public static String vigenereDecrypt(String cphrText, String k){	
		char cipher = ' ';
		String s =  " ";
		int plainValue, cipherValue;//will hold ascii values of plain char and encrypted char
		int kLength = k.length();//length of key
		cphrText = cphrText.toUpperCase();//upper case everything
		k = k.toUpperCase();
		for(int i = 0; i<cphrText.length(); i++){
			plainValue = cphrText.charAt(i);
			if(plainValue>65 || plainValue< 132){//ascii values from 65 -> 132 represent all uppercase alphabet letters
				cipherValue = (((int)cphrText.charAt(i))-65-((int)k.charAt(i%kLength)-65))%26+65;//add ascii value of plaintext to the ascii value of the key
				//if index is larger than length of key, mod it to get it back to length of key then mod everything by 26(number of letters in the alphabet) to get proper values. 
				cipher = (char)cipherValue;//cast integer ascii to char and return it
				s += String.valueOf(cipher);
		}
			else{
				System.out.println("Enter proper values please");}	
			}
		return s;
	}

	/////////////////////////////////////////////////////////////////////////

	/**
	 * Create the frame.
	 */
	public MainGUI() {
		setTitle("CryptoMachine");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		contentPane = new JPanel();
		contentPane.setBackground(Color.BLACK);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new CardLayout(0, 0));			

		///////////////////////////PANELS//////////////////////////////////////
		
		
				
		final JPanel mainMenu = new JPanel();
		mainMenu.setBackground(Color.BLACK);
		contentPane.add(mainMenu, "name_143298328342604");
		mainMenu.setLayout(null);
		mainMenu.setVisible(true);
		
		final JPanel menuPanel = new JPanel();
		menuPanel.setBackground(Color.DARK_GRAY);
		menuPanel.setBounds(18, 73, 401, 140);
		mainMenu.add(menuPanel);
		menuPanel.setLayout(null);
		
		final JPanel pictureEncryptOption = new JPanel();
		pictureEncryptOption.setBackground(Color.BLACK);
		contentPane.add(pictureEncryptOption, "name_143308333271907");
		pictureEncryptOption.setLayout(null); 
		pictureEncryptOption.setVisible(false);
		
		final JPanel imageDisplayed = new JPanel();
		imageDisplayed.setBackground(Color.BLACK);
		imageDisplayed.setBounds(6, 156, 428, 106);
		pictureEncryptOption.add(imageDisplayed);
		imageDisplayed.setLayout(null);
		imageDisplayed.setVisible(true);

			
		
		final JPanel TextEncryptOptions = new JPanel();
		TextEncryptOptions.setBackground(Color.BLACK);
		contentPane.add(TextEncryptOptions, "name_143305733883626");
		TextEncryptOptions.setLayout(null); 
		TextEncryptOptions.setVisible(false);
		
		final JPanel textMenu = new JPanel();
		textMenu.setBounds(0, 0, 440, 268);
		TextEncryptOptions.add(textMenu);
		textMenu.setBackground(Color.BLACK);
		textMenu.setLayout(null);
		textMenu.setVisible(false);
		
		final JPanel aesDisplay = new JPanel();
		aesDisplay.setBackground(Color.BLACK);
		contentPane.add(aesDisplay, "name_82488985997210");
		aesDisplay.setLayout(null);
		aesDisplay.setVisible(false);

		
		final JPanel caesarPanel = new JPanel();
		contentPane.add(caesarPanel, "name_61093389463179");
		caesarPanel.setBackground(Color.BLACK);
		caesarPanel.setLayout(null);
		caesarPanel.setVisible(false);
		
		final JPanel vigenereCipher = new JPanel();
		vigenereCipher.setBackground(Color.BLACK);
		contentPane.add(vigenereCipher, "name_116854126053549");
		vigenereCipher.setLayout(null);
		
		////////////////////////////////LABELS///////////////////////////////
		
		JLabel lblNewLabel = new JLabel("Machine");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setFont(new Font("Strasua", Font.BOLD, 27));
		lblNewLabel.setForeground(Color.BLUE);
		lblNewLabel.setBounds(157, 6, 229, 40);
		mainMenu.setVisible(true);
		mainMenu.add(lblNewLabel);
		
		JLabel titleCrypto = new JLabel("Crypto");
		titleCrypto.setHorizontalAlignment(SwingConstants.CENTER);
		titleCrypto.setForeground(Color.WHITE);
		titleCrypto.setFont(new Font("Papyrus", Font.BOLD, 29));
		titleCrypto.setBounds(40, 11, 242, 40);
		mainMenu.add(titleCrypto);
		
		JLabel welcomeMessage = new JLabel("Welcome to CryptoMachine.");
		welcomeMessage.setBounds(100, 18, 213, 27);
		menuPanel.add(welcomeMessage);
		welcomeMessage.setHorizontalAlignment(SwingConstants.CENTER);
		welcomeMessage.setForeground(Color.WHITE);
		welcomeMessage.setFont(new Font("Papyrus", Font.PLAIN, 17));
		
		JLabel gettingStartedLabel = new JLabel("To get started, select the datatype to encrypt.");
		gettingStartedLabel.setBounds(6, 44, 388, 27);
		menuPanel.add(gettingStartedLabel);
		gettingStartedLabel.setHorizontalAlignment(SwingConstants.CENTER);
		gettingStartedLabel.setFont(new Font("Papyrus", Font.PLAIN, 17));
		gettingStartedLabel.setForeground(Color.WHITE);
		
		JLabel lblNewLabel_1 = new JLabel("Made by Dora Goczi");
		lblNewLabel_1.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_1.setForeground(Color.BLUE);
		lblNewLabel_1.setBounds(6, 246, 428, 16);
		mainMenu.add(lblNewLabel_1);
		
		JLabel errorMessage_1 = new JLabel("");//displays error message for caesar program
		errorMessage_1.setForeground(Color.WHITE);
		errorMessage_1.setBounds(36, 193, 374, 16);
		caesarPanel.add(errorMessage_1);
		
		
		JLabel lblShiftBy = new JLabel("Shift By: ");//label for number to be shifted by
		lblShiftBy.setForeground(Color.WHITE);
		lblShiftBy.setBounds(16, 109, 58, 17);
		caesarPanel.add(lblShiftBy);
		lblShiftBy.setFont(new Font("Lucida Grande", Font.PLAIN, 14));
		
		JLabel lblPlaintext = new JLabel("Plaintext: ");
		lblPlaintext.setForeground(Color.WHITE);
		lblPlaintext.setBounds(16, 71, 68, 17);
		caesarPanel.add(lblPlaintext);
		lblPlaintext.setFont(new Font("Lucida Grande", Font.PLAIN, 14));
		
		JLabel caesraLabel = new JLabel("Caesar Shift");
		caesraLabel.setForeground(Color.BLUE);
		caesraLabel.setBounds(6, 14, 428, 31);
		caesarPanel.add(caesraLabel);
		caesraLabel.setHorizontalAlignment(SwingConstants.CENTER);
		caesraLabel.setFont(new Font("Silom", Font.BOLD, 27));
		
		JLabel lblCypherText = new JLabel("Cipher Text");
		lblCypherText.setForeground(Color.BLUE);
		lblCypherText.setBounds(6, 218, 428, 16);
		caesarPanel.add(lblCypherText);
		lblCypherText.setHorizontalAlignment(SwingConstants.CENTER);

		JLabel lblImageHasBeen = new JLabel("Image has been");
		lblImageHasBeen.setForeground(Color.BLUE);
		lblImageHasBeen.setBounds(158, 178, 107, 16);
		pictureEncryptOption.add(lblImageHasBeen);
		
		JLabel lblEncrypted_1 = new JLabel("ENCRYPTED");
		lblEncrypted_1.setHorizontalAlignment(SwingConstants.CENTER);
		lblEncrypted_1.setForeground(Color.RED);
		lblEncrypted_1.setBounds(158, 206, 107, 16);
		pictureEncryptOption.add(lblEncrypted_1);
		
		JLabel lblEnterTextTo = new JLabel("Enter text to encrypt:");
		lblEnterTextTo.setForeground(Color.WHITE);
		lblEnterTextTo.setBounds(37, 61, 159, 16);
		aesDisplay.add(lblEnterTextTo);
		
		JLabel lblEncrypted = new JLabel("Encrypted/Decrypted text");
		lblEncrypted.setForeground(Color.WHITE);
		lblEncrypted.setBounds(35, 173, 360, 16);
		aesDisplay.add(lblEncrypted);
		
		JLabel aesTitle = new JLabel("AES Encryption");
		aesTitle.setHorizontalAlignment(SwingConstants.CENTER);
		aesTitle.setFont(new Font("Silom", Font.BOLD, 24));
		aesTitle.setForeground(Color.BLUE);
		aesTitle.setBounds(6, 21, 428, 29);
		aesDisplay.add(aesTitle);
		
		JLabel lblPlaintext_1 = new JLabel("Plaintext");
		lblPlaintext_1.setForeground(Color.WHITE);
		lblPlaintext_1.setBounds(28, 63, 79, 16);
		vigenereCipher.add(lblPlaintext_1);
		
		JLabel lblKey = new JLabel("Key");
		lblKey.setForeground(Color.WHITE);
		lblKey.setBounds(26, 116, 61, 16);
		vigenereCipher.add(lblKey);
		
		
		JLabel lblImageEncryption = new JLabel("AES Image Encryption");
		lblImageEncryption.setHorizontalAlignment(SwingConstants.CENTER);
		lblImageEncryption.setFont(new Font("Silom", Font.BOLD, 19));
		lblImageEncryption.setForeground(Color.BLUE);
		lblImageEncryption.setBounds(6, 6, 428, 24);
		pictureEncryptOption.add(lblImageEncryption);
		pictureEncryptOption.setVisible(false);
		
		JLabel imgLabel = new JLabel(" ");
		imgLabel.setBounds(139, 6, 147, 95);
		imageDisplayed.add(imgLabel);
		
		
		JLabel lblChooseFileTo = new JLabel("Choose file to encrypt");
		lblChooseFileTo.setForeground(Color.WHITE);
		lblChooseFileTo.setBounds(23, 63, 139, 16);
		pictureEncryptOption.add(lblChooseFileTo);
	
		
		JLabel lblCipherText = new JLabel("Cipher Text");
		lblCipherText.setForeground(Color.BLUE);
		lblCipherText.setBounds(28, 192, 79, 16);
		vigenereCipher.add(lblCipherText);
		
		JLabel lblNewLabel_2 = new JLabel("Vigenère Cipher");
		lblNewLabel_2.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel_2.setFont(new Font("Silom", Font.PLAIN, 24));
		lblNewLabel_2.setForeground(Color.BLUE);
		lblNewLabel_2.setBounds(6, 6, 434, 45);
		vigenereCipher.add(lblNewLabel_2);
				
		///////////////////////////TEXT FIELDS///////////////////////////////////////
		
		
		JTextPane txtpnSubstitutionCipher = new JTextPane();
		txtpnSubstitutionCipher.setText("Vigenère Cipher");
		txtpnSubstitutionCipher.setForeground(Color.WHITE);
		txtpnSubstitutionCipher.setFont(new Font("Papyrus", Font.PLAIN, 21));
		txtpnSubstitutionCipher.setEditable(false);
		txtpnSubstitutionCipher.setBackground(Color.BLACK);
		txtpnSubstitutionCipher.setBounds(17, 125, 192, 36);
		textMenu.add(txtpnSubstitutionCipher);
		
		JTextPane txtpnCaesarShiftCipher = new JTextPane();//Caesar label
		txtpnCaesarShiftCipher.setFont(new Font("Papyrus", Font.PLAIN, 21));
		txtpnCaesarShiftCipher.setBounds(17, 53, 192, 36);
		textMenu.add(txtpnCaesarShiftCipher);
		txtpnCaesarShiftCipher.setEditable(false);
		txtpnCaesarShiftCipher.setForeground(Color.WHITE);
		txtpnCaesarShiftCipher.setText("Caesar Shift Cipher");
		txtpnCaesarShiftCipher.setBackground(Color.BLACK);

		JTextPane txtpnAesencryption = new JTextPane();//aes label
		txtpnAesencryption.setText("AES Encryption");
		txtpnAesencryption.setForeground(Color.WHITE);
		txtpnAesencryption.setFont(new Font("Papyrus", Font.PLAIN, 20));
		txtpnAesencryption.setEditable(false);
		txtpnAesencryption.setBackground(Color.BLACK);
		txtpnAesencryption.setBounds(17, 201, 164, 36);
		textMenu.add(txtpnAesencryption);
		
		
		JTextArea aesEncryptedField = new JTextArea();
		aesEncryptedField.setEditable(false);
		aesEncryptedField.setBounds(35, 198, 360, 42);
		aesDisplay.add(aesEncryptedField);
		
		plainVigenere = new JTextField();
		plainVigenere.setBounds(26, 78, 308, 26);
		vigenereCipher.add(plainVigenere);
		plainVigenere.setColumns(10);
		
		keyVigenere = new JTextField();
		keyVigenere.setBounds(26, 131, 130, 26);
		vigenereCipher.add(keyVigenere);
		keyVigenere.setColumns(10);
		
		cipherVigenere = new JTextField();
		cipherVigenere.setBounds(26, 210, 382, 26);
		vigenereCipher.add(cipherVigenere);
		cipherVigenere.setColumns(10);
		plainTextField = new JTextField();//field for entering plaintext(caesar)
		plainTextField.setBounds(86, 67, 308, 26);
		caesarPanel.add(plainTextField);
		plainTextField.setColumns(10);
		
		cypherTextField = new JTextField();//field for outputting cipher text(caesar)
		cypherTextField.setBounds(36, 234, 371, 26);
		caesarPanel.add(cypherTextField);
		cypherTextField.setColumns(10);
		cypherTextField.setEditable(false);
		
		displayPathofFile = new JTextField();
		displayPathofFile.setEditable(false);
		displayPathofFile.setBounds(23, 91, 396, 16);
		pictureEncryptOption.add(displayPathofFile);
		displayPathofFile.setColumns(10);
		
		aesplainField = new JTextField();
		aesplainField.setBounds(35, 78, 360, 29);
		aesDisplay.add(aesplainField);
		aesplainField.setColumns(10);
		
		

		////////////////////////////BUTTONS////////////////////////////////////////		
		
		
		JComboBox comboBox = new JComboBox();
		comboBox.setModel(new DefaultComboBoxModel(new String[] {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25"}));
		comboBox.setMaximumRowCount(25);
		comboBox.setBounds(86, 106, 68, 27);
		caesarPanel.add(comboBox);
		
		JButton caesarButton = new JButton("Caesar Program");
		caesarButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TextEncryptOptions.setVisible(false);
				textMenu.setVisible(false);
				aesDisplay.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				vigenereCipher.setVisible(false);
				caesarPanel.setVisible(true);
			}
		});
		caesarButton.setBounds(221, 43, 134, 47);
		textMenu.add(caesarButton);
		
		JButton btnShift = new JButton("SHIFT!");
		btnShift.setBounds(168, 143, 117, 51);
		caesarPanel.add(btnShift);
		
		
		JButton btnNewButton = new JButton("AES Program");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textMenu.setVisible(false);
				TextEncryptOptions.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(true);
			}
		});
		btnNewButton.setBounds(220, 190, 135, 47);
		textMenu.add(btnNewButton);
		
		JButton btnSubsProgram = new JButton("Vigenère Program");
		btnSubsProgram.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textMenu.setVisible(false);
				TextEncryptOptions.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				vigenereCipher.setVisible(true);
			}
		});
		btnSubsProgram.setBounds(221, 114, 134, 47);
		textMenu.add(btnSubsProgram);
		
		JButton backButton = new JButton("←");
		backButton.setToolTipText("Back to text menu");
		backButton.setFont(new Font("Lucida Grande", Font.PLAIN, 16));
		backButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textMenu.setVisible(false);
				TextEncryptOptions.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				vigenereCipher.setVisible(false);
				mainMenu.setVisible(true);
				menuPanel.setVisible(true);

			}
		});

		backButton.setBackground(Color.BLACK);//Black By Default
		backButton.setForeground(Color.BLUE);//Set as a Gray Colour 
		backButton.setBounds(6, 6, 58, 29);
		textMenu.add(backButton);
		
		JButton imageBackButton = new JButton("←");
		imageBackButton.setToolTipText("Back to text menu");
		imageBackButton.setFont(new Font("Lucida Grande", Font.PLAIN, 16));
		imageBackButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textMenu.setVisible(false);
				TextEncryptOptions.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				vigenereCipher.setVisible(false);
				pictureEncryptOption.setVisible(false);
				imageDisplayed.setVisible(false);
				mainMenu.setVisible(true);
				menuPanel.setVisible(true);

			}
		});
		
		
		JButton btnDecrypt = new JButton("DECRYPT!");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				String cipher = plainVigenere.getText();
				String key = keyVigenere.getText();
				cipherVigenere.setText(cipher);		
				
			}
		});
		btnDecrypt.setBounds(217, 162, 117, 29);
		vigenereCipher.add(btnDecrypt);
		
		
		JButton vigenereEncryptButton = new JButton("ENCRYPT!");
		vigenereEncryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String plainText = plainVigenere.getText();
				String key = keyVigenere.getText();
				cipherVigenere.setText(vigenereEncrypt(plainText, key));				
				
			}
		});
		vigenereEncryptButton.setBounds(217, 131, 117, 29);
		vigenereCipher.add(vigenereEncryptButton);
		

		imageBackButton.setBackground(Color.BLACK);//Black By Default
		imageBackButton.setForeground(Color.BLUE);//Set as a Gray Colour 
		imageBackButton.setBounds(6, 6, 58, 29);
		pictureEncryptOption.add(imageBackButton);
		
		JButton caesarInfo = new JButton("i");
		caesarInfo.setToolTipText("Caesar Shift Wikipedia Page");
		caesarInfo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage("https://en.wikipedia.org/wiki/Caesar_cipher");
			}
		});
		caesarInfo.setFont(new Font("Lucida Grande", Font.BOLD, 16));
		caesarInfo.setForeground(Color.BLUE);
		caesarInfo.setBounds(367, 47, 33, 42);
		textMenu.add(caesarInfo);
		

		
		JButton subsInfo = new JButton("i");
		subsInfo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage("http://www.counton.org/explorer/codebreaking/vigenere-cipher.php");
			}
		});
		subsInfo.setToolTipText("Substitution Cipher Wikipedia Page");
		subsInfo.setForeground(Color.BLUE);
		subsInfo.setFont(new Font("Lucida Grande", Font.BOLD, 16));
		subsInfo.setBounds(367, 119, 33, 42);
		textMenu.add(subsInfo);
		
		JButton aesInfo = new JButton("i");
		aesInfo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage("https://en.wikipedia.org/wiki/Advanced_Encryption_Standard");
			}
		});
		aesInfo.setToolTipText("AES Encryption Wikipedia Page");
		aesInfo.setForeground(Color.BLUE);
		aesInfo.setFont(new Font("Lucida Grande", Font.BOLD, 16));
		aesInfo.setBounds(367, 190, 33, 42);
		textMenu.add(aesInfo);
		
		JButton encImageButton = new JButton("Image");
		encImageButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				mainMenu.setVisible(false);
				TextEncryptOptions.setVisible(false);
				textMenu.setVisible(false);
				pictureEncryptOption.setVisible(true);
				imageDisplayed.setVisible(true);
				
			}
		});
		encImageButton.setBounds(218, 94, 117, 29);
		menuPanel.add(encImageButton);
		
		JButton aesEncryptButton = new JButton("ENCRYPT");
		aesEncryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{
 
						String plaintext = aesplainField.getText();//1. Get the input message string
						AESEncryption aes = new AESEncryption("thisisasecretkey");//creates object of class AESEncryption by specifying secret key which will be used
						String encrypted = aes.encrypt(plaintext);//Data to be encrypted
						aesEncryptedField.setText(encrypted);
						}
	
					catch(Exception E){
						System.out.println("oops there was an error");
					}
				}
				
		});
		aesEncryptButton.setBounds(35, 119, 117, 29);
		aesDisplay.add(aesEncryptButton);
		
		JButton aesDecryptButton = new JButton("DECRYPT");
		aesDecryptButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{
						String encryptedText = aesplainField.getText();//1. Get the input message string
						//AESEncryption aes = new AESEncryption("thisisasecretkey");//creates object of class AESEncryption by specifying secret key which will be used
						//String encrypted = decrypt(encryptedText);//Data to be encrypted
						aesEncryptedField.setText(encryptedText);
						}
					catch(Exception E){
						System.out.println("oops there was an error");
					}
				}
				
		});
		aesDecryptButton.setBounds(278, 120, 117, 29);
		aesDisplay.add(aesDecryptButton);
		
		JButton aesBackButton = new JButton("←");
		aesBackButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TextEncryptOptions.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				TextEncryptOptions.setVisible(true);
				textMenu.setVisible(true);	
			}
		});
		aesBackButton.setForeground(Color.BLUE);
		aesBackButton.setFont(new Font("Lucida Grande", Font.PLAIN, 16));
		aesBackButton.setBackground(Color.BLACK);
		aesBackButton.setBounds(6, 6, 58, 29);
		aesDisplay.add(aesBackButton);

		JButton btnText = new JButton("Text");
		btnText.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				mainMenu.setVisible(false);
				TextEncryptOptions.setVisible(true);
				textMenu.setVisible(true);
			}
		});
		btnText.setBounds(64, 94, 117, 29);
		menuPanel.add(btnText);
		
		JButton caesarBackButton = new JButton("←");
		caesarBackButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TextEncryptOptions.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				vigenereCipher.setVisible(false);
				TextEncryptOptions.setVisible(true);
				textMenu.setVisible(true);	
				
			}
		});
		caesarBackButton.setForeground(Color.BLUE);
		caesarBackButton.setFont(new Font("Lucida Grande", Font.PLAIN, 16));
		caesarBackButton.setBackground(Color.BLACK);
		caesarBackButton.setBounds(6, 6, 58, 29);
		caesarPanel.add(caesarBackButton);
		
		JButton vigenereBackButton = new JButton("←");
		vigenereBackButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				TextEncryptOptions.setVisible(false);
				mainMenu.setVisible(false);
				menuPanel.setVisible(false);
				caesarPanel.setVisible(false);
				aesDisplay.setVisible(false);
				vigenereCipher.setVisible(false);
				TextEncryptOptions.setVisible(true);
				textMenu.setVisible(true);		
			}
		});
		vigenereBackButton.setForeground(Color.BLUE);
		vigenereBackButton.setFont(new Font("Lucida Grande", Font.PLAIN, 16));
		vigenereBackButton.setBackground(Color.BLACK);
		vigenereBackButton.setBounds(6, 6, 58, 29);
		vigenereCipher.add(vigenereBackButton);
		
		
	
		
		JButton imgEncrypt = new JButton("ENCRYPT");
		imgEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					FileInputStream fileIn = new FileInputStream(displayPathofFile.getText());
					FileOutputStream fileOut = new FileOutputStream("Encrypted.jpg");
					byte[] keyByteArray = "ThisIsASecretKey".getBytes();//16 bit string converted to bits for AES key
					SecretKeySpec key = new SecretKeySpec(keyByteArray, "AES");//constructs AES secret key from previous byte array created
					Cipher encObj = Cipher.getInstance("AES");//creates a cipher object based on AES
					encObj.init(Cipher.ENCRYPT_MODE, key);//initializes cipher object to encryption mode
					CipherOutputStream strmOut = new CipherOutputStream(fileOut , encObj);//creates encrypted file
					byte[] tempBuff = new byte[1024];//temporary storage for image bytes until it is transferred into a new image file -> Encrypted.jpg
					int read;
					while((read=fileIn.read(tempBuff))!=-1){//true until reading into the temporary storage is done
						strmOut.write(tempBuff,0,read);//writes data from temporary storage from 0 until length of read
					}
					fileIn.close();//close the intial jpg file
					fileOut.flush();//flushes output stream and forces any buffered output to be written out
					strmOut.close();//close created encrypted jpg file
					imageDisplayed.setVisible(false);
					
				} catch (Exception e1) {
					e1.printStackTrace();//if file is not found throw this generate error message
					JOptionPane.showMessageDialog(null, e1);
				}
				
			}
		});
		imgEncrypt.setBounds(73, 115, 117, 29);
		pictureEncryptOption.add(imgEncrypt);
		
		JButton imgDecrypt = new JButton("DECRYPT");
		imgDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				imageDisplayed.setVisible(true);
			}
		});
		imgDecrypt.setBounds(225, 115, 117, 29);
		pictureEncryptOption.add(imgDecrypt);
		
		

		
		JButton btnChoose = new JButton("Choose");
		btnChoose.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {


				String filePath = " ";//will receive absolute path of file and then display it on the button
				JFileChooser fileChooser = new JFileChooser(); //provides mechanism for user to open a file
				fileChooser.showOpenDialog(null);
				File img = fileChooser.getSelectedFile();
				filePath = img.getAbsolutePath();//gets absolute file path of image chosen and stores it as string
				displayPathofFile.setText(filePath);//sets the text in the text box to display path
				
				ImageIcon imageIcon = new ImageIcon(filePath); // load the image to a imageIcon
				Image image = imageIcon.getImage(); // transform it 
				Image newimg = image.getScaledInstance(120, 120,  java.awt.Image.SCALE_SMOOTH); // scale image 
				imageIcon = new ImageIcon(newimg);  // transform it back
				JLabel label = new JLabel("", imageIcon, JLabel.CENTER);//creates label in which image icon will be stored in
				imgLabel.setIcon(imageIcon);	
				imageDisplayed.setLayout(null);
				imageDisplayed.add(imgLabel);//adds selected image icon to panel
				imageDisplayed.setVisible(true);
				
			}
		});
		btnChoose.setBounds(174, 58, 91, 29);
		pictureEncryptOption.add(btnChoose);
		

		
		
		btnShift.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{
					String plaintext = plainTextField.getText();//1. Get the input message string
					String stringShift = (String)comboBox.getSelectedItem();
					int shiftBy = Integer.parseInt(stringShift);//parses string into int
					String cipherText = caesarShift(plaintext, shiftBy);
					cypherTextField.setText(cipherText);
					//3. If either value is missing or inappropriate, give error message, clear output, terminate program
					checkForSpecialCharacters(plaintext);	
					}
				catch(NumberFormatException nfe){
					//when shift value is not an integer
					errorMessage_1.setText("Please enter an integer value for the shift.");
				}
				catch(Exception E){
					//This is for catching special characters
					errorMessage_1.setText("Please enter message with no sepcial characters.");
				}
			}
		}
		);	
		
		/////////////////////////////////////////////////////////////////////////////
	}
}
